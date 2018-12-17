package com.elmo.chapter1.in8;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.NoSuchMessageException;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.context.support.ResourceBundleMessageSource;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import java.util.Locale;

@Component
public class Translator {

    private static ResourceBundleMessageSource messageSource;

    @Autowired
    Translator(ResourceBundleMessageSource messageSource) {
        Translator.messageSource = messageSource;
    }

    public static String toLocale(String msgCode) {
        Locale locale = LocaleContextHolder.getLocale();
        return messageSource.getMessage(msgCode, null, locale);
    }

    /**
     * 设置当前的返回信息
     *
     * @param request
     * @param code
     * @return
     */
    public String getMessage(HttpServletRequest request, String code) {

        String lauage = request.getHeader("Accept-Language");
        //默认没有就是请求地区的语言
        Locale locale = null;
        if (lauage == null) {
            locale = request.getLocale();
        } else if ("en-US".equals(lauage)) {
            locale = Locale.ENGLISH;
        } else if ("zh-CN".equals(lauage)) {
            locale = Locale.CHINA;
        }
        //其余的不正确的默认就是本地的语言
        else {
            locale = request.getLocale();
        }
        String result = null;
        try {
            result = messageSource.getMessage(code, null, locale);
        } catch (NoSuchMessageException e) {
        }
        if (result == null) {
            return code;
        }
        return result;
    }


}
