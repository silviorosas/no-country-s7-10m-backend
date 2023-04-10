package s710m.noCountry.server.mapper;

import org.springframework.stereotype.Component;
import s710m.noCountry.server.model.ServiceCategory;
import s710m.noCountry.server.model.dto.ServiceCategoryResponseDto;

@Component
public class ServiceCategoryMapper {

    public ServiceCategoryResponseDto toDto(ServiceCategory serviceCategory){
        ServiceCategoryResponseDto dto = new ServiceCategoryResponseDto();
        dto.setId(serviceCategory.getId());
        dto.setName(serviceCategory.getName().getName());
        return dto;
    }
}
