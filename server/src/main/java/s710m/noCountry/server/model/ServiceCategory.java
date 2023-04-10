package s710m.noCountry.server.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import s710m.noCountry.server.model.enums.NameServiceCategory;

import javax.persistence.*;

import java.util.ArrayList;
import java.util.List;

import static javax.persistence.EnumType.STRING;
import static javax.persistence.GenerationType.IDENTITY;

@Entity
@Table(name = "service_category")
@Setter
@Getter
@NoArgsConstructor
@AllArgsConstructor
public class ServiceCategory {

    @Id
    @GeneratedValue(strategy = IDENTITY)
    @Column(name = "id")
    private Long id;

    @Enumerated(STRING)
    @Column(name = "name")
    private NameServiceCategory name;

    @ManyToMany
    @JoinTable(name = "category_provider",
            joinColumns = @JoinColumn(name = "category_id"),
            inverseJoinColumns = @JoinColumn(name = "provider_id"))
    @JsonIgnoreProperties("serviceCategories")
    private List<ServiceProvider> serviceProviders = new ArrayList<>();
}
