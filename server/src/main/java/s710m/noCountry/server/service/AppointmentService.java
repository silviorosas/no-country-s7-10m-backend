package s710m.noCountry.server.service;

import s710m.noCountry.server.model.Appointment;
import s710m.noCountry.server.model.dto.AppointmentRequestDto;
import s710m.noCountry.server.model.dto.AppointmentResponseDto;

import java.util.List;
import java.util.Optional;

public interface AppointmentService {


    public AppointmentResponseDto saveAppointment(AppointmentRequestDto dto) throws Exception;

    public void deleteAppointment(Long appointmentId);

    public List<Appointment> getAllAppointments();

    public Appointment updateAppointment (Long id, Appointment appointment );

    public Optional<Appointment> searchById(Long id);



}
