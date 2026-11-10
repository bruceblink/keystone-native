package app.keystone.job;

import com.fasterxml.jackson.databind.JavaType;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.inject.Any;
import jakarta.enterprise.inject.Instance;
import jakarta.inject.Inject;
import jakarta.inject.Named;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Discovers and invokes explicitly annotated CDI job methods. */
@ApplicationScoped
public class JobInvocationService {
    private static final Pattern TARGET = Pattern.compile("^([A-Za-z][A-Za-z0-9_]*)\\.([A-Za-z][A-Za-z0-9_]*)\\(\\)$");

    @Inject @Any Instance<Object> beans;
    @Inject SystemJobTasks systemJobTasks;
    @Inject ObjectMapper objectMapper;

    private volatile Map<String, Invocation> invocations;

    public List<JobTarget> targets() {
        return invocations().values().stream()
                .map(Invocation::jobTarget)
                .sorted(Comparator.comparing(JobTarget::group).thenComparing(JobTarget::name).thenComparing(JobTarget::invokeTarget))
                .toList();
    }

    public void validate(String target, String params) {
        Invocation invocation = find(target);
        resolveArguments(invocation.method(), params);
    }

    public void invoke(String target, String params) {
        Invocation invocation = find(target);
        try {
            Method method = invocation.method();
            if (!method.canAccess(invocation.bean())) method.setAccessible(true);
            method.invoke(invocation.bean(), resolveArguments(method, params));
        } catch (InvocationTargetException e) {
            Throwable cause = e.getCause() == null ? e : e.getCause();
            throw new IllegalStateException("scheduled job failed: " + cause.getMessage(), cause);
        } catch (ReflectiveOperationException | RuntimeException e) {
            throw new IllegalStateException("could not invoke scheduled job " + target, e);
        }
    }

    private Map<String, Invocation> invocations() {
        Map<String, Invocation> cached = invocations;
        if (cached != null) return cached;
        synchronized (this) {
            if (invocations != null) return invocations;
            Map<String, Invocation> discovered = new LinkedHashMap<>();
            List<Object> candidates = new ArrayList<>();
            candidates.add(systemJobTasks);
            for (Object bean : beans) if (bean != systemJobTasks) candidates.add(bean);
            for (Object bean : candidates) {
                Class<?> type = userClass(bean.getClass());
                String beanName = beanName(bean, type);
                for (Method method : methods(type)) {
                    JobTask annotation = method.getAnnotation(JobTask.class);
                    if (annotation == null || Modifier.isStatic(method.getModifiers()) || method.getParameterCount() > 1) continue;
                    String target = beanName + "." + method.getName() + "()";
                    if (discovered.putIfAbsent(target, new Invocation(bean, method, target, annotation)) != null) {
                        throw new IllegalStateException("duplicate scheduled job target: " + target);
                    }
                }
            }
            invocations = Map.copyOf(discovered);
            return invocations;
        }
    }

    private Invocation find(String target) {
        if (target == null || !TARGET.matcher(target.trim()).matches()) {
            throw new IllegalArgumentException("invokeTarget must match bean.method()");
        }
        Invocation invocation = invocations().get(target.trim());
        if (invocation == null) throw new IllegalArgumentException("unknown invokeTarget: " + target);
        return invocation;
    }

    private Object[] resolveArguments(Method method, String params) {
        if (method.getParameterCount() == 0) return new Object[0];
        try {
            String json = params == null || params.isBlank() ? "{}" : params;
            JavaType type = objectMapper.getTypeFactory().constructType(method.getGenericParameterTypes()[0]);
            return new Object[] {objectMapper.readValue(json, type)};
        } catch (Exception e) {
            throw new IllegalArgumentException("jobParams is not valid for the invokeTarget", e);
        }
    }

    private static List<Method> methods(Class<?> type) {
        List<Method> result = new ArrayList<>();
        for (Class<?> current = type; current != null && current != Object.class; current = current.getSuperclass()) {
            for (Method method : current.getDeclaredMethods()) result.add(method);
        }
        return result;
    }

    private static Class<?> userClass(Class<?> type) {
        Class<?> current = type;
        while (current.getName().contains("$Subclass") || current.getName().contains("_ClientProxy")) {
            current = current.getSuperclass();
        }
        return current;
    }

    private static String beanName(Object bean, Class<?> type) {
        Named named = type.getAnnotation(Named.class);
        if (named != null && !named.value().isBlank()) return named.value();
        String simple = type.getSimpleName();
        return Character.toLowerCase(simple.charAt(0)) + simple.substring(1);
    }

    private record Invocation(Object bean, Method method, String target, JobTask metadata) {
        public JobTarget jobTarget() {
            String name = metadata.name().isBlank() ? method.getName() : metadata.name();
            return new JobTarget(target, name, metadata.group(), metadata.description());
        }
    }

    public record JobTarget(String invokeTarget, String name, String group, String description) {}
}
