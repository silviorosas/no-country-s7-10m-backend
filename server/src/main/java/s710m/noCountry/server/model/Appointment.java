package s710m.noCountry.server.model;

import com.fasterxml.jackson.annotation.JsonFormat;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import javax.persistence.*;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name="appointments")
public class Appointment {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY, cascade = CascadeType.REFRESH)
    @JoinColumn(name = "client_id",nullable = false)
    private Client client;

    @ManyToOne(fetch = FetchType.LAZY, cascade = CascadeType.REFRESH)
    @JoinColumn(name = "serviceProvider_id", nullable = false)
    private ServiceProvider serviceProvider;

    @Column(name = "problem_description")
    private String problemDescription;

    @ElementCollection(targetClass = String.class)
    private List<String> problemPhotos = new ArrayList<>();

    @Column
    @JsonFormat(pattern="yyyy-MM-dd HH:mm:ss")
    // @JsonFormat(pattern="yyyy-MM-dd")
    private LocalDateTime date;


}
