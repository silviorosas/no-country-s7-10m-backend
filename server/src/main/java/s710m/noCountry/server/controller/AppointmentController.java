package s710m.noCountry.server.controller;


import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import s710m.noCountry.server.model.Appointment;
import s710m.noCountry.server.model.dto.AppointmentRequestDto;
import s710m.noCountry.server.model.dto.AppointmentResponseDto;
import s710m.noCountry.server.service.AppointmentService;

import javax.persistence.EntityNotFoundException;
import java.util.List;
import java.util.Optional;

@RestController
@RequestMapping("/api/appointment")
@CrossOrigin(origins = "http://localhost:3000")
@RequiredArgsConstructor
public class AppointmentController {

    private final AppointmentService service;

    ////End point para obtener todos los turnos GET= "/turnos/"
    @GetMapping
    public ResponseEntity<List<Appointment>> getAll() {
        List<Appointment>listAppointment= service.getAllAppointments();
        return new ResponseEntity<>(listAppointment, HttpStatus.OK);
    }

    ////End point para actualizar todos los turnos PUT= "/turnos/"
    @PutMapping("/{id}")
    public ResponseEntity<Appointment> update(@PathVariable Long id, @RequestBody Appointment appointment) {
        Appointment updatedAppointment = service.updateAppointment(id,appointment);
        return new ResponseEntity<>(updatedAppointment, HttpStatus.OK);
    }


    ////End point para guardar  turnos POST= "/turnos/"
    @PostMapping
    public ResponseEntity<AppointmentResponseDto> save(@RequestBody AppointmentRequestDto dto) throws Exception {
        AppointmentResponseDto createdAppointment= service.saveAppointment(dto);
        return new ResponseEntity<>(createdAppointment, HttpStatus.CREATED);
    }

    ////End point para eliminar por id todos los turnos DELETE= "/turnos/3"
    @DeleteMapping("/{appointmentId}")
    public void delete(@PathVariable("appointmentId") Long appointmentId) {
        service.deleteAppointment(appointmentId);
    }


    ////End point para obtener  POR ID todos los turnos GET= "/turnos/3"
    @GetMapping("/{id}")
    public ResponseEntity<Optional<Appointment>> searchById(@PathVariable Long id) throws EntityNotFoundException {
        Optional<Appointment> appointment= service.searchById(id);
        return new ResponseEntity<>(appointment,HttpStatus.OK);
    }


}
