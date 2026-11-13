package app.keystone.notice;

import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** 验证公告管理使用 ORM。 */
class NoticePersistenceTest {
    @Test
    void repositoryUsesOrmWithoutManualJdbc() throws Exception {
        String source = Files.readString(Path.of("src/main/java/app/keystone/notice/NoticeRepository.java"));
        assertTrue(source.contains("PanacheRepositoryBase<NoticeEntity"));
        assertTrue(source.contains("publish"));
        assertFalse(source.contains("DataSource"));
        assertFalse(source.contains("prepareStatement"));
    }
}
