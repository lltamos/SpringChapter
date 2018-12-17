package com.elmo.chapter1.in8;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.MessageSource;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.support.ReloadableResourceBundleMessageSource;

@Configuration
public class WebI18nConfig {

    @Value("${spring.messages.basename}")
    private String basename;
    @Value("${spring.messages.cache-duration}")
    private long cacheMillis;

    @Value("${spring.messages.encoding}")
    private String encoding;


    @Bean
    public MessageSource initMessageSource() {
        ReloadableResourceBundleMessageSource messageSource = new ReloadableResourceBundleMessageSource();
        System.out.println("baseName====>:" + this.basename);
        messageSource.setBasename(basename);
        messageSource.setDefaultEncoding(encoding);
        messageSource.setCacheMillis(cacheMillis);
        return messageSource;
    }



}
