package com.elmo.chapter1.in8;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.support.ResourceBundleMessageSource;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import org.springframework.web.servlet.i18n.AcceptHeaderLocaleResolver;

import javax.servlet.http.HttpServletRequest;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;

/**
 * 在Spring Boot 1.5版本都是靠重写WebMvcConfigurerAdapter的方法来添加自定义拦截器，消息转换器等。
 * SpringBoot 2.0 后，该类被标记为@Deprecated。因此我们只能靠实现WebMvcConfigurer接口来实现。
 */
@Configuration
public class CustomLocaleResolver
        extends AcceptHeaderLocaleResolver
        implements WebMvcConfigurer {

    @Value("${spring.messages.basename}")
    private String basename;

    @Value("${spring.messages.encoding}")
    private String encoding;

     List<Locale> LOCALES = Arrays.asList(
            new Locale("en-US"),
            new Locale("zh-CN"));

    @Override
    public Locale resolveLocale(HttpServletRequest request) {

        System.out.println("*************************************************");
        String headerLang = request.getHeader("Accept-Language");
        return headerLang == null || headerLang.isEmpty()
                ? Locale.getDefault()
                : Locale.lookup(Locale.LanguageRange.parse(headerLang), LOCALES);
    }

    @Bean
    public ResourceBundleMessageSource messageSource() {
        ResourceBundleMessageSource rs = new ResourceBundleMessageSource();
        rs.setBasename(basename);
        rs.setDefaultEncoding(encoding);
        rs.setCacheMillis(-1);
        rs.setUseCodeAsDefaultMessage(true);
        return rs;
    }
}
