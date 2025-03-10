// package com.example.matching.Scheduler;

// import org.springframework.beans.factory.annotation.Autowired;
// import org.springframework.scheduling.annotation.Scheduled;
// import org.springframework.stereotype.Component;

// import com.example.matching.model.User;
// import com.example.matching.repository.UserRepository;

// import java.util.List;

// @Component
// public class AccountUnlockScheduler {

//     @Autowired
//     private UserRepository userRepository;

//     @Scheduled(fixedRate = 300000) // Runs every 5 minutes
//     public void unlockAccounts() {
//         List<User> lockedUsers = userRepository.findAllLockedUsers(); // Method to fetch locked users
//         long currentTime = System.currentTimeMillis();

//         for (User user : lockedUsers) {
//             if (currentTime >= user.getLockTime() + (5 * 60 * 1000)) {
//                 user.setAccountLocked(false);
//                 user.setFailedLoginAttempts(0); // Reset failed attempts
//                 userRepository.save(user); // Save changes
//             }
//         }
//     }
// }
