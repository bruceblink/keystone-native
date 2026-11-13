package app.keystone.post;

import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** 验证岗位管理使用 ORM。 */
class PostPersistenceTest {
    @Test
    void repositoryUsesOrmWithoutManualJdbc() throws Exception {
        String source = Files.readString(Path.of("src/main/java/app/keystone/post/PostRepository.java"));
        assertTrue(source.contains("PanacheRepositoryBase<PostEntity"));
        assertTrue(source.contains("PESSIMISTIC_WRITE"));
        assertFalse(source.contains("DataSource"));
        assertFalse(source.contains("prepareStatement"));
    }
}
