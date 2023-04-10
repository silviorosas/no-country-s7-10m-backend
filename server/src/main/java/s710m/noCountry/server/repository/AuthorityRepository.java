package s710m.noCountry.server.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import s710m.noCountry.server.model.Authority;

@Repository
public interface AuthorityRepository extends JpaRepository<Authority,Long> {
}
