package app.keystone.file;

import app.keystone.ApiResponse;
import app.keystone.auth.RequiresPermission;
import app.keystone.auth.AuthorizationContext;
import app.keystone.auth.AuthorizationService;
import io.quarkus.security.identity.SecurityIdentity;
import jakarta.inject.Inject;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.jboss.resteasy.reactive.RestForm;
import org.jboss.resteasy.reactive.multipart.FileUpload;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.UUID;

@Path("/v1/file")
@app.keystone.auth.RequiresDataScope("file")
public class FileResource {
    private final java.nio.file.Path root;
    @Inject SecurityIdentity identity;
    @Inject AuthorizationService authorization;

    @Inject
    public FileResource(@ConfigProperty(name = "keystone.file.root") String root) { this.root = Paths.get(root).toAbsolutePath().normalize(); }

    @POST @Path("/upload") @RequiresPermission("file:write") @Consumes(MediaType.MULTIPART_FORM_DATA) @Produces(MediaType.APPLICATION_JSON)
    public Response upload(@RestForm("file") FileUpload file) { authorization.require(context(), "file:write", "file"); if (file == null) return bad("file is required"); try { return Response.ok(ApiResponse.ok(save(file))).build(); } catch (IOException e) { return Response.serverError().entity(ApiResponse.error("file upload failed")).build(); } }

    @POST @Path("/uploads") @RequiresPermission("file:write") @Consumes(MediaType.MULTIPART_FORM_DATA) @Produces(MediaType.APPLICATION_JSON)
    public Response uploads(@RestForm("files") List<FileUpload> files) {
        authorization.require(context(), "file:write", "file");
        if (files == null || files.isEmpty() || files.stream().anyMatch(Objects::isNull)) return bad("files are required");
        List<Upload> uploads = new ArrayList<>(files.size());
        try {
            for (FileUpload file : files) uploads.add(save(file));
            return Response.ok(ApiResponse.ok(uploads)).build();
        } catch (IOException | FileUploadException e) {
            // 批量保存失败时清理本次已写入文件，避免部分成功产生不可追踪的残留文件。
            cleanup(uploads);
            return Response.serverError().entity(ApiResponse.error("file upload failed")).build();
        }
    }

    @GET @Path("/download") @RequiresPermission("file:read") @Produces(MediaType.APPLICATION_OCTET_STREAM)
    public Response download(@QueryParam("fileName") String fileName) { authorization.require(context(), "file:read", "file"); try { java.nio.file.Path path = safePath(fileName); if (!Files.isRegularFile(path)) return Response.status(Response.Status.NOT_FOUND).entity(ApiResponse.error("file not found")).type(MediaType.APPLICATION_JSON).build(); String name = path.getFileName().toString(); return Response.ok(Files.readAllBytes(path)).header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + name + "\"").build(); } catch (IllegalArgumentException e) { return bad(e.getMessage()); } catch (IOException e) { return Response.serverError().entity(ApiResponse.error("file download failed")).type(MediaType.APPLICATION_JSON).build(); } }

    private Upload save(FileUpload file) throws IOException {
        Files.createDirectories(root);
        String original = file.fileName() == null ? "file" : Paths.get(file.fileName()).getFileName().toString();
        String extension = "";
        int dot = original.lastIndexOf('.'); if (dot > 0 && dot < original.length() - 1) extension = original.substring(dot).toLowerCase(java.util.Locale.ROOT).replaceAll("[^a-z0-9.]", "");
        String generated = UUID.randomUUID() + extension;
        java.nio.file.Path target = safePath(generated); Files.copy(file.uploadedFile(), target);
        return new Upload("/api/v1/file/download?fileName=" + generated, generated, generated, original);
    }

    private java.nio.file.Path safePath(String fileName) {
        if (fileName == null || fileName.isBlank()) throw new IllegalArgumentException("fileName is required");
        java.nio.file.Path path = root.resolve(fileName).normalize();
        if (!path.startsWith(root) || fileName.contains("\\") || fileName.contains("\0")) throw new IllegalArgumentException("invalid fileName");
        return path;
    }

    private void cleanup(List<Upload> uploads) {
        for (Upload upload : uploads) {
            try { Files.deleteIfExists(safePath(upload.fileName())); } catch (IOException | IllegalArgumentException ignored) { }
        }
    }

    private AuthorizationContext context() { return authorization.context(identity); }

    private static Response bad(String message) { return Response.status(422).entity(ApiResponse.error(message)).type(MediaType.APPLICATION_JSON).build(); }
    public record Upload(String url, String fileName, String newFileName, String originalFilename) {}
    private static final class FileUploadException extends RuntimeException { private FileUploadException(Throwable cause) { super(cause); } }
}
