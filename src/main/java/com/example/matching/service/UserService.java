package com.example.matching.service;

import com.example.matching.model.User;
import com.example.matching.model.UserDto;

import java.util.Optional;

public interface UserService {
    void registerUser(UserDto userDto);

    Optional<User> findUserByEmail(String email);

    void updatePassword(User user, String newPassword);
}

// ! End

// package com.example.matching.service;

// import com.example.matching.model.UserDto;

// public interface UserService {
// void registerUser(UserDto userDto);
// }

// !

// package com.example.matching.service;

// import com.example.matching.model.UserDto;

// // UserService.java

// public interface UserService {
// void registerUser(UserDto userDto);
// }
