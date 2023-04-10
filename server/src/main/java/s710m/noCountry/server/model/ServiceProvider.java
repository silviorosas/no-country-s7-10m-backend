package s710m.noCountry.server.model;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.hibernate.annotations.SQLDelete;
import org.hibernate.annotations.Where;

import javax.persistence.*;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static javax.persistence.GenerationType.IDENTITY;

@Entity
@Table(name = "service_provider")
@Setter
@Getter
@NoArgsConstructor
@AllArgsConstructor
@SQLDelete(sql = "UPDATE service_provider SET deleted = true WHERE id = ?")
@Where(clause = "deleted = false")
public class ServiceProvider {

    @Id
    @GeneratedValue(strategy = IDENTITY)
    @Column(name = "id")
    private Long id;

    @Column(name = "full_name")
    private String fullName;

    @Column(name = "country")
    private String country;

    @ManyToMany(mappedBy = "serviceProviders")
    @JsonIgnoreProperties("serviceProviders")
    private List<ServiceCategory> serviceCategories = new ArrayList<>();

    @Column(name = "experience_years")
    private String experienceYears;

    @Column(name = "suggest_offers_from")
    private String suggestOffersFrom;

    @Column(name = "km_around")
    private String kmAround;

    @Column(name = "profile_photo")
    private String profilePhoto;

    @Column(name = "profile_description")
    private String profileDescription;

    @ElementCollection(targetClass = String.class)
    private List<String> galleryPhotos = new ArrayList<>();

    @Column(name = "deleted")
    private Boolean deleted = Boolean.FALSE;

    @OneToOne
    @JoinColumn(name = "user_id")
    @JsonIgnoreProperties("serviceProvider")
    private User user;

    @JsonIgnore
    @OneToMany(mappedBy = "serviceProvider",fetch = FetchType.LAZY)
    private Set<Appointment> appointment= new HashSet<>();
}
