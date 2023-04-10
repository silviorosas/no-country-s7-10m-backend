package s710m.noCountry.server.model.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Setter
@Getter
@AllArgsConstructor
@NoArgsConstructor
public class ServiceProviderResponseDto {
    private Long idUser;
    private String email;
    private String fullName;
    private String country;
    private String experienceYears;
}
