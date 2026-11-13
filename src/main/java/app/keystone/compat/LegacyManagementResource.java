package app.keystone.compat;

import app.keystone.ApiResponse;
import app.keystone.audit.OperationLogRepository;
import app.keystone.auth.RequiresPermission;
import app.keystone.auth.DataScopeService;
import app.keystone.config.SystemConfig;
import app.keystone.config.SystemConfigRepository;
import app.keystone.dept.Department;
import app.keystone.dept.DepartmentRepository;
import app.keystone.dict.DictionaryItem;
import app.keystone.dict.DictionaryRepository;
import app.keystone.dict.DictionaryType;
import app.keystone.menu.Menu;
import app.keystone.menu.MenuRepository;
import app.keystone.notice.Notice;
import app.keystone.notice.NoticeRepository;
import app.keystone.post.Post;
import app.keystone.post.PostRepository;
import app.keystone.user.UserRepository;
import io.quarkus.security.identity.SecurityIdentity;
import jakarta.inject.Inject;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

/** Compatibility routes used by the original Keystone administration frontend. */
@Path("/system")
@Produces(MediaType.APPLICATION_JSON)
public class LegacyManagementResource {
    @Inject DepartmentRepository departments;
    @Inject DictionaryRepository dictionaries;
    @Inject SystemConfigRepository configs;
    @Inject MenuRepository menus;
    @Inject NoticeRepository notices;
    @Inject PostRepository posts;
    @Inject OperationLogRepository logs;
    @Inject SecurityIdentity identity;
    @Inject DataScopeService dataScopes;
    @Inject UserRepository users;

    @GET @Path("/depts") @RequiresPermission("department:read") public ApiResponse<List<Department>> depts() { return ApiResponse.ok(departments.list(departmentScope())); }
    @GET @Path("/depts/dropdown") @RequiresPermission("department:read") public ApiResponse<List<Department>> deptDropdown() { return ApiResponse.ok(departments.list(departmentScope())); }
    @GET @Path("/dept/{id}") @RequiresPermission("department:read") public Response dept(@PathParam("id") long id) { return response(find(departments.list(departmentScope()), id, "department not found")); }
    @POST @Path("/dept") @Consumes(MediaType.APPLICATION_JSON) @RequiresPermission("department:write") public Response addDept(DeptCommand request) { if (request == null) return bad("request body is required"); if (!departmentScope().allowsDepartmentCreation(request.parentId())) return forbidden(); try { var value = departments.create(request.codeValue(), request.nameValue(), request.parentId(), request.sortValue()); logs.record(actor(), "CREATE", "department", String.valueOf(value.id()), value.code()); return created(value); } catch (IllegalArgumentException e) { return bad(e.getMessage()); } }
    @PUT @Path("/dept/{id}") @Consumes(MediaType.APPLICATION_JSON) @RequiresPermission("department:write") public Response editDept(@PathParam("id") long id, DeptCommand request) { if (request == null) return bad("request body is required"); if (!departmentScope().allowsDepartmentUpdate(id, request.parentId())) return forbidden(); try { var value = departments.update(id, request.nameValue(), request.parentId(), request.sortValue(), request.enabled()); logs.record(actor(), "UPDATE", "department", String.valueOf(id), value.code()); return response(value); } catch (IllegalArgumentException e) { return bad(e.getMessage()); } catch (java.util.NoSuchElementException e) { return notFound("department not found"); } }
    @DELETE @Path("/dept/{id}") @RequiresPermission("department:write") public Response removeDept(@PathParam("id") long id) { if (!departmentScope().allowsDepartment(id)) return forbidden(); try { departments.delete(id); logs.record(actor(), "DELETE", "department", String.valueOf(id), null); return response(Map.of("deleted", true)); } catch (IllegalArgumentException e) { return bad(e.getMessage()); } catch (java.util.NoSuchElementException e) { return notFound("department not found"); } }

    @GET @Path("/dict/types") @RequiresPermission("dictionary:read") public ApiResponse<List<DictionaryType>> dictTypes() { return ApiResponse.ok(dictionaries.types()); }
    @GET @Path("/dict/type/list") @RequiresPermission("dictionary:read") public ApiResponse<List<DictionaryType>> dictTypeList() { return dictTypes(); }
    @GET @Path("/dict/type/{id}") @RequiresPermission("dictionary:read") public Response dictType(@PathParam("id") long id) { return response(dictionaries.types().stream().filter(v -> v.id() == id).findFirst().orElseThrow(() -> new NotFoundException("dictionary type not found"))); }
    @POST @Path("/dict/type") @Consumes(MediaType.APPLICATION_JSON) @RequiresPermission("dictionary:write") public Response addDictType(DictTypeCommand request) { if (request == null) return bad("request body is required"); try { var value = dictionaries.createType(request.codeValue(), request.nameValue()); logs.record(actor(), "CREATE", "dictionary-type", String.valueOf(value.id()), value.code()); return created(value); } catch (IllegalArgumentException e) { return bad(e.getMessage()); } }
    @PUT @Path("/dict/type/{id}") @Consumes(MediaType.APPLICATION_JSON) @RequiresPermission("dictionary:write") public Response editDictType(@PathParam("id") long id, DictTypeCommand request) { if (request == null) return bad("request body is required"); var current = dictionaries.types().stream().filter(v -> v.id() == id).findFirst().orElseThrow(() -> new NotFoundException("dictionary type not found")); try { return response(dictionaries.updateType(current.code(), request.nameValue(), request.enabled())); } catch (IllegalArgumentException e) { return bad(e.getMessage()); } }
    @DELETE @Path("/dict/type/{id}") @RequiresPermission("dictionary:write") public Response removeDictType(@PathParam("id") long id) { var current = dictionaries.types().stream().filter(v -> v.id() == id).findFirst().orElseThrow(() -> new NotFoundException("dictionary type not found")); dictionaries.deleteType(current.code()); return response(Map.of("deleted", true)); }
    @DELETE @Path("/dict/cache") @RequiresPermission("dictionary:write") public Response clearDictCache() { return response(Map.of("cleared", true)); }
    @GET @Path("/dict/data/list") @RequiresPermission("dictionary:read") public ApiResponse<List<DictionaryItem>> dictDataList(@QueryParam("typeCode") String typeCode) { return ApiResponse.ok(typeCode == null ? dictionaries.types().stream().flatMap(type -> dictionaries.items(type.code()).stream()).toList() : dictionaries.items(typeCode)); }
    @GET @Path("/dict/data/type/{typeCode}") @RequiresPermission("dictionary:read") public ApiResponse<List<DictionaryItem>> dictDataByType(@PathParam("typeCode") String typeCode) { return ApiResponse.ok(dictionaries.items(typeCode)); }
    @GET @Path("/dict/data/{id}") @RequiresPermission("dictionary:read") public Response dictData(@PathParam("id") long id) { return response(findItem(id)); }
    @POST @Path("/dict/data") @Consumes(MediaType.APPLICATION_JSON) @RequiresPermission("dictionary:write") public Response addDictData(DictDataCommand request) { if (request == null) return bad("request body is required"); try { var value = dictionaries.createItem(request.typeCodeValue(), request.valueValue(), request.labelValue(), request.sortValue()); return created(value); } catch (IllegalArgumentException e) { return bad(e.getMessage()); } catch (java.util.NoSuchElementException e) { return notFound(e.getMessage()); } }
    @PUT @Path("/dict/data/{id}") @Consumes(MediaType.APPLICATION_JSON) @RequiresPermission("dictionary:write") public Response editDictData(@PathParam("id") long id, DictDataCommand request) { if (request == null) return bad("request body is required"); try { return response(dictionaries.updateItem(id, request.labelValue(), request.sortValue(), request.enabled())); } catch (java.util.NoSuchElementException e) { return notFound(e.getMessage()); } }
    @DELETE @Path("/dict/data/{id}") @RequiresPermission("dictionary:write") public Response removeDictData(@PathParam("id") long id) { try { dictionaries.deleteItem(id); return response(Map.of("deleted", true)); } catch (java.util.NoSuchElementException e) { return notFound(e.getMessage()); } }

    @GET @Path("/configs") @RequiresPermission("config:read") public ApiResponse<List<SystemConfig>> configs() { return ApiResponse.ok(configs.list()); }
    @GET @Path("/config/{id}") @RequiresPermission("config:read") public Response config(@PathParam("id") long id) { return response(configs.list().stream().filter(v -> v.id() == id).findFirst().orElseThrow(() -> new NotFoundException("config not found"))); }
    @POST @Path("/config") @Consumes(MediaType.APPLICATION_JSON) @RequiresPermission("config:write") public Response addConfig(ConfigCommand request) { if (request == null) return bad("request body is required"); try { var value = configs.create(request.keyValue(), request.valueValue(), request.description); return created(value); } catch (IllegalArgumentException e) { return bad(e.getMessage()); } }
    @PUT @Path("/config/{id}") @Consumes(MediaType.APPLICATION_JSON) @RequiresPermission("config:write") public Response editConfig(@PathParam("id") long id, ConfigCommand request) { if (request == null) return bad("request body is required"); var current = configs.list().stream().filter(v -> v.id() == id).findFirst().orElseThrow(() -> new NotFoundException("config not found")); return response(configs.update(current.key(), request.valueValue(), request.description, request.enabled)); }
    @DELETE @Path("/configs/cache") @RequiresPermission("config:write") public Response clearConfigCache() { return response(Map.of("cleared", true)); }

    @GET @Path("/menus") @RequiresPermission("menu:read") public ApiResponse<List<Menu>> menuList() { return ApiResponse.ok(menus.listForRoles(List.of("ADMIN"))); }
    @GET @Path("/menus/{id}") @RequiresPermission("menu:read") public Response menu(@PathParam("id") long id) { return response(menus.listForRoles(List.of("ADMIN")).stream().filter(v -> v.id() == id).findFirst().orElseThrow(() -> new NotFoundException("menu not found"))); }
    @GET @Path("/menus/dropdown") @RequiresPermission("menu:read") public ApiResponse<List<Menu>> menuDropdown() { return ApiResponse.ok(menus.listForRoles(List.of("ADMIN"))); }
    @POST @Path("/menus") @Consumes(MediaType.APPLICATION_JSON) @RequiresPermission("menu:write") public Response addMenu(MenuRepository.MenuRequest request) { if (request == null) return bad("request body is required"); try { var value = menus.create(request); logs.record(actor(), "CREATE", "menu", String.valueOf(value.id()), value.code()); return created(value); } catch (IllegalArgumentException e) { return bad(e.getMessage()); } }
    @PUT @Path("/menus/{id}") @Consumes(MediaType.APPLICATION_JSON) @RequiresPermission("menu:write") public Response editMenu(@PathParam("id") long id, MenuRepository.MenuRequest request) { if (request == null) return bad("request body is required"); try { var value = menus.update(id, request); logs.record(actor(), "UPDATE", "menu", String.valueOf(id), value.code()); return response(value); } catch (IllegalArgumentException e) { return bad(e.getMessage()); } catch (java.util.NoSuchElementException e) { return notFound("menu not found"); } }
    @PUT @Path("/menus/{id}/roles") @Consumes(MediaType.APPLICATION_JSON) @RequiresPermission("menu:write") public Response assignMenuRoles(@PathParam("id") long id, MenuRoleCommand request) { if (request == null) return bad("request body is required"); try { menus.assignRoles(id, request.roleCodes); return response(Map.of("updated", true)); } catch (IllegalArgumentException e) { return bad(e.getMessage()); } }
    @DELETE @Path("/menus/{id}") @RequiresPermission("menu:write") public Response removeMenu(@PathParam("id") long id) { try { menus.delete(id); logs.record(actor(), "DELETE", "menu", String.valueOf(id), null); return response(Map.of("deleted", true)); } catch (IllegalArgumentException e) { return bad(e.getMessage()); } catch (java.util.NoSuchElementException e) { return notFound("menu not found"); } }

    @GET @Path("/notices") @RequiresPermission("notice:read") public ApiResponse<List<Notice>> noticeList() { return ApiResponse.ok(notices.list(false)); }
    @GET @Path("/notices/database/slave") @RequiresPermission("notice:read") public ApiResponse<List<Notice>> noticeSlaveList() { return noticeList(); }
    @GET @Path("/notices/{id}") @RequiresPermission("notice:read") public Response notice(@PathParam("id") long id) { return response(notices.list(false).stream().filter(v -> v.id() == id).findFirst().orElseThrow(() -> new NotFoundException("notice not found"))); }
    @DELETE @Path("/notices") @RequiresPermission("notice:write") public Response removeNotices(@QueryParam("ids") String ids) { return deleteNotices(ids); }
    @POST @Path("/notices") @Consumes(MediaType.APPLICATION_JSON) @RequiresPermission("notice:write") public Response addNotice(NoticeCommand request) { if (request == null) return bad("request body is required"); try { return created(notices.create(request.title, request.content, request.noticeType, actor())); } catch (IllegalArgumentException e) { return bad(e.getMessage()); } }
    @PUT @Path("/notices/{id}") @Consumes(MediaType.APPLICATION_JSON) @RequiresPermission("notice:write") public Response editNotice(@PathParam("id") long id, NoticeCommand request) { if (request == null) return bad("request body is required"); try { return response(notices.update(id, request.title, request.content, request.noticeType, request.enabled)); } catch (java.util.NoSuchElementException e) { return notFound("notice not found"); } }
    @DELETE @Path("/notices/{id}") @RequiresPermission("notice:write") public Response removeNotice(@PathParam("id") long id) { try { notices.delete(id); return response(Map.of("deleted", true)); } catch (java.util.NoSuchElementException e) { return notFound("notice not found"); } }

    @GET @Path("/post/list") @RequiresPermission("post:read") public ApiResponse<List<Post>> postList() { return ApiResponse.ok(posts.list()); }
    @GET @Path("/post/excel") @RequiresPermission("post:read") public Response postExport() { var rows = new java.util.ArrayList<String[]>(); rows.add(new String[]{"id", "code", "name", "sortOrder", "enabled"}); for (Post post : posts.list()) rows.add(new String[]{String.valueOf(post.id()), post.code(), post.name(), String.valueOf(post.sortOrder()), String.valueOf(post.enabled())}); return CsvExport.response("posts.csv", rows); }
    @GET @Path("/post/{id}") @RequiresPermission("post:read") public Response post(@PathParam("id") long id) { return response(posts.list().stream().filter(v -> v.id() == id).findFirst().orElseThrow(() -> new NotFoundException("post not found"))); }
    @POST @Path("/post") @Consumes(MediaType.APPLICATION_JSON) @RequiresPermission("post:write") public Response addPost(PostCommand request) { if (request == null) return bad("request body is required"); try { return created(posts.create(request.codeValue(), request.nameValue(), request.sortValue())); } catch (IllegalArgumentException e) { return bad(e.getMessage()); } }
    @PUT @Path("/post") @Consumes(MediaType.APPLICATION_JSON) @RequiresPermission("post:write") public Response editPost(PostCommand request) { if (request == null || request.id == null) return bad("id is required"); try { return response(posts.update(request.id, request.nameValue(), request.sortValue(), request.enabled)); } catch (java.util.NoSuchElementException e) { return notFound("post not found"); } }
    @DELETE @Path("/post") @RequiresPermission("post:write") public Response removePosts(@QueryParam("ids") String ids) { if (ids == null || ids.isBlank()) return bad("ids is required"); try { int count = 0; for (Long id : parseIds(ids)) { posts.delete(id); count++; } return response(Map.of("deleted", count)); } catch (NumberFormatException e) { return bad("ids must be comma separated numbers"); } }

    private DictionaryItem findItem(long id) { return dictionaries.types().stream().flatMap(type -> dictionaries.items(type.code()).stream()).filter(item -> item.id() == id).findFirst().orElseThrow(() -> new NotFoundException("dictionary item not found")); }
    private Response deleteNotices(String ids) { if (ids == null || ids.isBlank()) return bad("ids is required"); try { int count = 0; for (Long id : parseIds(ids)) { notices.delete(id); count++; } return response(Map.of("deleted", count)); } catch (NumberFormatException e) { return bad("ids must be comma separated numbers"); } }
    private String actor() { return identity.getPrincipal().getName(); }
    /** 兼容路由必须复用现代部门查询的范围策略，避免绕过数据范围条件。 */
    private DataScopeService.Scope departmentScope() { return dataScopes.forUser(subjectId()); }
    private long subjectId() {
        Object value = identity.getAttribute("userId");
        if (value instanceof Number number) return number.longValue();
        return users.findAuthUserByUsername(identity.getPrincipal().getName())
                .orElseThrow(() -> new NotAuthorizedException("subject not found")).id();
    }
    private static List<Long> parseIds(String ids) { return Arrays.stream(ids.split(",")).map(String::trim).map(Long::valueOf).toList(); }
    private static <T> Response response(T value) { return Response.ok(ApiResponse.ok(value)).build(); }
    private static <T> Response created(T value) { return Response.status(Response.Status.CREATED).entity(ApiResponse.ok(value)).build(); }
    private static Response bad(String message) { return Response.status(Response.Status.BAD_REQUEST).entity(ApiResponse.error(message)).build(); }
    private static Response forbidden() { return Response.status(Response.Status.FORBIDDEN).entity(ApiResponse.error("data scope denied")).build(); }
    private static Response notFound(String message) { return Response.status(Response.Status.NOT_FOUND).entity(ApiResponse.error(message)).build(); }
    private static <T> T find(List<T> values, long id, String message) { return values.stream().filter(value -> idOf(value) == id).findFirst().orElseThrow(() -> new NotFoundException(message)); }
    private static long idOf(Object value) { if (value instanceof Department v) return v.id(); throw new IllegalArgumentException("unsupported id lookup"); }

    public record DeptCommand(Long id, String code, String name, String deptName, Long parentId, Integer sortOrder, Integer orderNum, Boolean enabled) { String codeValue() { return code == null ? "dept-" + System.nanoTime() : code; } String nameValue() { return name == null ? deptName : name; } int sortValue() { return sortOrder == null ? (orderNum == null ? 0 : orderNum) : sortOrder; } }
    public record DictTypeCommand(Long id, String code, String name, String dictCode, String dictName, Boolean enabled) { String codeValue() { return code == null ? dictCode : code; } String nameValue() { return name == null ? dictName : name; } }
    public record DictDataCommand(String typeCode, String dictType, String value, String dictValue, String label, String dictLabel, Integer sortOrder, Integer dictSort, Boolean enabled) { String typeCodeValue() { return typeCode == null ? dictType : typeCode; } String valueValue() { return value == null ? dictValue : value; } String labelValue() { return label == null ? dictLabel : label; } int sortValue() { return sortOrder == null ? (dictSort == null ? 0 : dictSort) : sortOrder; } }
    public record ConfigCommand(Long id, String key, String configKey, String value, String configValue, String description, Boolean enabled) { String keyValue() { return key == null ? configKey : key; } String valueValue() { return value == null ? configValue : value; } }
    public record NoticeCommand(Long id, String title, String content, String noticeType, Boolean enabled) {}
    public record PostCommand(Long id, String code, String name, String postCode, String postName, Integer sortOrder, Integer postSort, Boolean enabled) { String codeValue() { return code == null ? postCode : code; } String nameValue() { return name == null ? postName : name; } int sortValue() { return sortOrder == null ? (postSort == null ? 0 : postSort) : sortOrder; } }
    public record MenuRoleCommand(List<String> roleCodes) {}
}
