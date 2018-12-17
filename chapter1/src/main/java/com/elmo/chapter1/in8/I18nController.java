package com.elmo.chapter1.in8;

import org.springframework.context.MessageSource;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.annotation.Resource;
@RestController
public class I18nController {

    @Resource
    private MessageSource messageSource;

    @GetMapping(value = "/api")
    public String getMessage() {
        return Translator.toLocale("mess.user.name");
    }


}
