package stirling.software.spdf.enterprise.config.caching;

import java.util.Set;
import org.springframework.cache.CacheManager;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.cache.concurrent.ConcurrentMapCache;
import org.springframework.cache.concurrent.ConcurrentMapCacheFactoryBean;
import org.springframework.cache.support.SimpleCacheManager;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
@EnableCaching
public class CacheConfiguration {

    @Bean
    ConcurrentMapCacheFactoryBean registrationsCache() {
        ConcurrentMapCacheFactoryBean cache = new ConcurrentMapCacheFactoryBean();
        cache.setName("relying-party-registrations-cache");
        return cache;
    }

    @Bean
    CacheManager cacheManager(ConcurrentMapCache registrationsCache) {
        SimpleCacheManager cacheManager = new SimpleCacheManager();
        cacheManager.setCaches(Set.of(registrationsCache));
        return cacheManager;
    }
}
