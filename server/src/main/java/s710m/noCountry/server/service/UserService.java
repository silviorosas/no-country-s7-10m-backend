package s710m.noCountry.server.service;

import s710m.noCountry.server.model.dto.LoginRequestDto;

public interface UserService {
    Object login(LoginRequestDto dto);
}
