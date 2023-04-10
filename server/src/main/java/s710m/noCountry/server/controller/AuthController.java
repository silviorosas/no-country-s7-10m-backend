package s710m.noCountry.server.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import s710m.noCountry.server.model.dto.LoginRequestDto;
import s710m.noCountry.server.service.UserService;

import static org.springframework.http.HttpStatus.*;

@RestController
@RequestMapping("api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final UserService service;

    @PostMapping("/login")
    public ResponseEntity<Object> login(@RequestBody LoginRequestDto dto){
        return ResponseEntity.status(OK).body(service.login(dto));
    }

}
