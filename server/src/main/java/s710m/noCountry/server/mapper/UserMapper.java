package s710m.noCountry.server.mapper;

import org.springframework.stereotype.Component;
import s710m.noCountry.server.model.Client;
import s710m.noCountry.server.model.ServiceProvider;
import s710m.noCountry.server.model.User;
import s710m.noCountry.server.model.dto.LoginClientResponseDto;
import s710m.noCountry.server.model.dto.LoginServiceProviderResponseDto;

import java.util.stream.Collectors;

@Component
public class UserMapper {

    public LoginClientResponseDto toClientDto(User user, Client client, String token){
        LoginClientResponseDto dto = new LoginClientResponseDto();
        dto.setToken(token);
        dto.setIdUser(user.getId());
        dto.setEmail(user.getUsername());
        dto.setFullName(client.getFullName());
        dto.setCountry(client.getCountry());
        return dto;
    }

    public LoginServiceProviderResponseDto toServiceProviderDto(User user, ServiceProvider serviceProvider, String token){
        LoginServiceProviderResponseDto dto = new LoginServiceProviderResponseDto();
        dto.setToken(token);
        dto.setIdUser(user.getId());
        dto.setEmail(user.getUsername());
        dto.setFullName(serviceProvider.getFullName());
        dto.setCountry(serviceProvider.getCountry());
        dto.setExperienceYears(serviceProvider.getExperienceYears());
        dto.setServiceCategories(
                serviceProvider.getServiceCategories()
                        .stream()
                        .map((c) -> c.getName().name())
                        .collect(Collectors.toList()));
        return dto;
    }

}
