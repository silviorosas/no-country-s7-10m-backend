package s710m.noCountry.server.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import s710m.noCountry.server.model.dto.ServiceCategoryResponseDto;
import s710m.noCountry.server.model.dto.ServiceProviderResponseDto;
import s710m.noCountry.server.service.ServiceCategoryService;

import java.util.List;

import static org.springframework.http.HttpStatus.OK;

@RestController
@RequiredArgsConstructor
@RequestMapping("api/service-categories")
public class ServiceCategoryController {

    private final ServiceCategoryService service;

    @GetMapping
    public ResponseEntity<List<ServiceCategoryResponseDto>> getAllServiceCategory(){
        return ResponseEntity.status(OK).body(service.getAllServiceCategories());
    }

    @GetMapping("/{id}")
    public ResponseEntity<List<ServiceProviderResponseDto>> getAllServiceProvidersByCategory(@PathVariable Long id){
        return ResponseEntity.status(OK).body(service.getAllServiceProvidersByCategory(id));
    }

}
