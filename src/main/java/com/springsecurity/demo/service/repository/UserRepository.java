package com.springsecurity.demo.service.repository;

import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

import com.springsecurity.demo.model.User;

@Repository("userRepository")
public interface UserRepository extends CrudRepository<User, String> {
	User findByEmailIdIgnoreCase(String emailId);
}
