package s710m.noCountry.server.mapper;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import s710m.noCountry.server.configException.EntityNotFoundException;
import s710m.noCountry.server.model.Appointment;
import s710m.noCountry.server.model.Client;
import s710m.noCountry.server.model.dto.AppointmentRequestDto;
import s710m.noCountry.server.model.dto.AppointmentResponseDto;
import s710m.noCountry.server.repository.ClientRepository;
import s710m.noCountry.server.repository.ServiceProviderRepository;

@Component
@RequiredArgsConstructor
public class AppointmentMapper {

    private final ClientRepository clientRepository;
    private final ServiceProviderRepository serviceProviderRepository;

    public Appointment toEntity(AppointmentRequestDto dto){
        Appointment appointment = new Appointment();
        appointment.setDate(dto.getDate());
        appointment.setProblemDescription(dto.getProblemDescription());
        appointment.setProblemPhotos(dto.getProblemPhotos());
        appointment.setClient(clientRepository
                .findById(dto.getIdClient())
                .orElseThrow( () -> new EntityNotFoundException("Client not found.")));
        appointment.setServiceProvider(serviceProviderRepository
                .findById(dto.getIdServiceProvider())
                .orElseThrow( () -> new EntityNotFoundException("Service Provider not found.")));
        return appointment;
    }

    public AppointmentResponseDto toDto(Appointment appointment){
        AppointmentResponseDto dto = new AppointmentResponseDto();
        dto.setDate(appointment.getDate());
        return dto;
    }
}
