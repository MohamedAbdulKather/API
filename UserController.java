package com.example.Final.controller;

import com.example.Final.Repo.TokenRepo;
import com.example.Final.Repo.UserRepository;
 import com.example.Final.Service.UserService;
import com.example.Final.config.ApiResponse;
import com.example.Final.config.JwtUtil;
import com.example.Final.config.SecurityConfig;
import com.example.Final.model.PasswordResetToken;
import com.example.Final.model.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.util.UUID;

@RestController
@RequestMapping("/api/users")
public class UserController {

    @Autowired
    private UserService userService;
    @Autowired
    PasswordEncoder passwordEncoder;

    @Autowired
    UserRepository userRepository;

    @Autowired
    TokenRepo tokenRepo;

    @PostMapping("/signup")
    public ResponseEntity<?> signUp(@RequestBody User user) {

        if (userService.findByEmail(user.getEmail()) != null) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(new ApiResponse(false, "Email already exists", null));
        }

        if (user.getUsername() == null || user.getUsername().isEmpty()) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(new ApiResponse(false, "Please enter a name", null));
        }

        if (user.getEmail() == null || user.getEmail().isEmpty()) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(new ApiResponse(false, "Please enter an email", null));
        }

        if (user.getPassword() == null || user.getPassword().isEmpty()) {
            return ResponseEntity.status(HttpStatus.CONFLICT)
                    .body(new ApiResponse(false, "Please enter a password", null));
        }

        userService.signUp(user);
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(new ApiResponse(true, "User registered successfully", null));
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody User user) {
        User existingUser = userService.findByEmail(user.getEmail());

        if (existingUser == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new ApiResponse(false, "Enter Valid Email", null));
        }

        if (!passwordEncoder.matches(user.getPassword(), existingUser.getPassword())) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new ApiResponse(false, "Enter Valid Password", null));
        }

         String token = JwtUtil.generateToken(existingUser.getEmail());
        return ResponseEntity.ok(new ApiResponse(true, "Login successful", token));

    }

    @PostMapping("/forgotPassword")
    public String forgotPassordProcess(@RequestParam User user) {
        String output = "";
        User users = userRepository.findByEmail(user.getEmail());
        if (users != null) {
            output = userService.sendEmail(users);
        }
        if (output.equals("success")) {
            return "forgotPassword?success";
        }
        return "redirect:/login?error";
    }


    @GetMapping("/resetPassword/{token}")
    public String resetPasswordForm(@PathVariable String token, Model model) {
        PasswordResetToken reset = tokenRepo.findByToken(token);
        if (reset != null && userService.hasExipred(reset.getExpiryDateTime())) {
            model.addAttribute("email", reset.getUser().getEmail());
            return "resetPassword";
        }
        return "redirect:/forgotPassword?error";
    }




    /*@PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody User user) {

        if (userService.findByEmail(user.getEmail()) != null) {
            return ResponseEntity.ok("Login successful");
        } else {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid credentials");
        }
    }*/



}
