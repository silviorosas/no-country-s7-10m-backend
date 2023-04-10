package s710m.noCountry.server.service;

import s710m.noCountry.server.model.ServiceCategory;
import s710m.noCountry.server.model.dto.ServiceCategoryResponseDto;
import s710m.noCountry.server.model.dto.ServiceProviderResponseDto;

import java.util.List;

public interface ServiceCategoryService {

    List<ServiceCategoryResponseDto> getAllServiceCategories();
    List<ServiceProviderResponseDto> getAllServiceProvidersByCategory(Long id);
    ServiceCategory getById(Long id);
}
