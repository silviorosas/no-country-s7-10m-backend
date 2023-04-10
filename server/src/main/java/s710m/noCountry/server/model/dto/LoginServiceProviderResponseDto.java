package s710m.noCountry.server.model.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.List;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class LoginServiceProviderResponseDto {

    private String token;
    private Long idUser;
    private String email;
    private String fullName;
    private String country;
    private String experienceYears;
    private List<String> serviceCategories;

}
