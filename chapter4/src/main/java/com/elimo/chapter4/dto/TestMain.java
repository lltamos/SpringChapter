package com.elimo.chapter4.dto;

public class TestMain {

    public void test1(UserInputDTO userInputDTO) {
        User user = new UserInputDTOConvert().convert(userInputDTO);
//        User saveUserResult = userService.addUser(user);
    }

    public void test2(UserInputDTO userInputDTO) {
        User user = userInputDTO.convertToUser();
        //        User saveUserResult = userService.addUser(user);
    }

    public UserDTO test3(UserDTO userDTO) {
        User user = userDTO.convertToUser();
//        User saveResultUser = userService.addUser(user);
        return userDTO.convertFor(user);
    }
}
