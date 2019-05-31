package com.elimo.chapter4.dto;

import lombok.Data;
import org.springframework.beans.BeanUtils;

@Data
public class UserInputDTO {
    private String username;
    private int age;

    public User convertToUser() {
        UserDTOConvert userDTOConvert = new UserDTOConvert();
        return userDTOConvert.convert(this);
    }

    private static class UserDTOConvert implements DTOConvert<UserInputDTO, User> {
        @Override
        public User convert(UserInputDTO userDTO) {
            User user = new User();
            BeanUtils.copyProperties(userDTO, user);
            return user;
        }

    }
}
