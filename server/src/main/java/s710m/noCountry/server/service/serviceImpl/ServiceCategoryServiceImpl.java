package s710m.noCountry.server.service.serviceImpl;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import s710m.noCountry.server.configException.EntityNotFoundException;
import s710m.noCountry.server.mapper.ServiceCategoryMapper;
import s710m.noCountry.server.mapper.ServiceProviderMapper;
import s710m.noCountry.server.model.ServiceCategory;
import s710m.noCountry.server.model.dto.ServiceCategoryResponseDto;
import s710m.noCountry.server.model.dto.ServiceProviderResponseDto;
import s710m.noCountry.server.repository.ServiceCategoryRepository;
import s710m.noCountry.server.service.ServiceCategoryService;

import java.util.List;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class ServiceCategoryServiceImpl implements ServiceCategoryService {

    private final ServiceCategoryRepository repository;
    private final ServiceCategoryMapper mapper;
    private final ServiceProviderMapper serviceProviderMapper;

    @Override
    public List<ServiceCategoryResponseDto> getAllServiceCategories() {
        return repository.findAll()
                .stream()
                .map(mapper::toDto)
                .collect(Collectors.toList());
    }

    @Override
    public List<ServiceProviderResponseDto> getAllServiceProvidersByCategory(Long id) {
        ServiceCategory serviceCategory = getById(id);
        return serviceCategory.getServiceProviders()
                .stream()
                .map(serviceProviderMapper::toDto)
                .collect(Collectors.toList());
    }

    @Override
    public ServiceCategory getById(Long id) {
        return repository.findById(id).orElseThrow(
                () -> new EntityNotFoundException("Category not found.")
        );
    }


}
