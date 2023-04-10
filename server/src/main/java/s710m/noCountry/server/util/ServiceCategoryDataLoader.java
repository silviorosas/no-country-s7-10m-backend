package s710m.noCountry.server.util;

import lombok.RequiredArgsConstructor;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;
import s710m.noCountry.server.model.ServiceCategory;
import s710m.noCountry.server.model.enums.NameServiceCategory;
import s710m.noCountry.server.repository.ServiceCategoryRepository;

import java.util.List;

@Component
@RequiredArgsConstructor
public class ServiceCategoryDataLoader implements CommandLineRunner {

    private final ServiceCategoryRepository repository;


    @Override
    public void run(String... args) throws Exception {
        categoriesLoad();
    }

    private void categoriesLoad(){
        if(repository.findAll().isEmpty()){
            ServiceCategory c1 = new ServiceCategory();
            c1.setName(NameServiceCategory.AC);

            ServiceCategory c2 = new ServiceCategory();
            c2.setName(NameServiceCategory.CARPENTER);

            ServiceCategory c3 = new ServiceCategory();
            c3.setName(NameServiceCategory.CEMENT_WORK);

            ServiceCategory c4 = new ServiceCategory();
            c4.setName(NameServiceCategory.COVERS_ROOF);

            ServiceCategory c5 = new ServiceCategory();
            c5.setName(NameServiceCategory.ELDERLY_CARE);

            ServiceCategory c6 = new ServiceCategory();
            c6.setName(NameServiceCategory.ELECTRICIAN);

            ServiceCategory c7 = new ServiceCategory();
            c7.setName(NameServiceCategory.FLOORS);

            ServiceCategory c8 = new ServiceCategory();
            c8.setName(NameServiceCategory.GLAZIERS);

            ServiceCategory c9 = new ServiceCategory();
            c9.setName(NameServiceCategory.HEATER);

            ServiceCategory c10 = new ServiceCategory();
            c10.setName(NameServiceCategory.HOME_REPAIR);

            ServiceCategory c11 = new ServiceCategory();
            c11.setName(NameServiceCategory.LADDER);

            ServiceCategory c12 = new ServiceCategory();
            c12.setName(NameServiceCategory.NANNY);

            ServiceCategory c13 = new ServiceCategory();
            c13.setName(NameServiceCategory.PAINTER);

            ServiceCategory c14 = new ServiceCategory();
            c14.setName(NameServiceCategory.PLUMBER);

            ServiceCategory c15 = new ServiceCategory();
            c15.setName(NameServiceCategory.TILER);

            ServiceCategory c16 = new ServiceCategory();
            c16.setName(NameServiceCategory.WALL_COVERING);

            ServiceCategory c17 = new ServiceCategory();
            c17.setName(NameServiceCategory.WALLPAPER);

            ServiceCategory c18 = new ServiceCategory();
            c18.setName(NameServiceCategory.WASHER_TECHNICIAN);

            List<ServiceCategory> categories = List.of(c1,c2,c3,c4,c5,c6,c7,c8,c9,c10,c11,c12,c13,c14,c15,c16,c17,c18);
            repository.saveAll(categories);
        }
    }
}
