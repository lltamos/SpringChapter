package com.elimo.chapter4.dto;

public interface DTOConvert<S,T> {
    T convert(S s);
}
