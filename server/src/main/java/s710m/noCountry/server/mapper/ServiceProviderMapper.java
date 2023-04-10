package s710m.noCountry.server.mapper;

import org.springframework.stereotype.Component;
import s710m.noCountry.server.model.ServiceProvider;
import s710m.noCountry.server.model.dto.ServiceProviderResponseDto;

@Component
public class ServiceProviderMapper {

    public ServiceProviderResponseDto toDto(ServiceProvider serviceProvider){
        ServiceProviderResponseDto dto = new ServiceProviderResponseDto();
        dto.setIdUser(serviceProvider.getUser().getId());
        dto.setEmail(serviceProvider.getUser().getUsername());
        dto.setFullName(serviceProvider.getFullName());
        dto.setCountry(serviceProvider.getCountry());
        dto.setExperienceYears(serviceProvider.getExperienceYears());
        return dto;
    }

}
