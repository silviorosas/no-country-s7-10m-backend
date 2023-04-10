package s710m.noCountry.server.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import s710m.noCountry.server.model.Client;

@Repository
public interface ClientRepository extends JpaRepository<Client,Long> {
}
