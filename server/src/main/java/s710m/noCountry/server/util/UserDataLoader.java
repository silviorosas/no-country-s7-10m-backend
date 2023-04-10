package s710m.noCountry.server.util;

import lombok.RequiredArgsConstructor;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;
import s710m.noCountry.server.model.Authority;
import s710m.noCountry.server.model.Client;
import s710m.noCountry.server.model.ServiceProvider;
import s710m.noCountry.server.model.User;
import s710m.noCountry.server.model.enums.NameAuthority;
import s710m.noCountry.server.repository.AuthorityRepository;
import s710m.noCountry.server.repository.ClientRepository;
import s710m.noCountry.server.repository.ServiceProviderRepository;
import s710m.noCountry.server.repository.UserRepository;

@Component
@RequiredArgsConstructor
public class UserDataLoader implements CommandLineRunner {

    private final UserRepository userRepository;
    private final AuthorityRepository authorityRepository;
    private final ClientRepository clientRepository;
    private final ServiceProviderRepository serviceProviderRepository;
    private final PasswordEncoder encoder;
    @Override
    public void run(String... args) throws Exception {
        loadRoles();
        loadUserClient();
        loadUserServiceProvider();
    }

    private void loadRoles(){
        if(authorityRepository.findAll().isEmpty()){
            Authority client = new Authority(1L, NameAuthority.ROLE_CLIENT,"");
            Authority serviceProvider = new Authority(2L, NameAuthority.ROLE_SERVICE_PROVIDER,"");
            authorityRepository.save(client);
            authorityRepository.save(serviceProvider);
        }
    }

    @Transactional
    private void loadUserClient(){
        if(clientRepository.findAll().isEmpty()){
            User userClient = new User();
            userClient.setEmail("user@userTest");
            userClient.setPassword(encoder.encode("1234"));
            userClient.getAuthorities().add(authorityRepository.findById(1L).get());
            User savedUserClient = userRepository.save(userClient);
            Client client = new Client();
            client.setFullName("User Client");
            client.setCountry("Argentina");
            client.setUser(savedUserClient);
            Client savedClient = clientRepository.save(client);
            savedUserClient.setClient(savedClient);
            userRepository.save(savedUserClient);
        }
    }

    @Transactional
    private void loadUserServiceProvider(){
        if(serviceProviderRepository.findAll().isEmpty()){
            User userServiceProvider = new User();
            userServiceProvider.setEmail("serviceProvider@profesional");
            userServiceProvider.setPassword(encoder.encode("1234"));
            userServiceProvider.getAuthorities().add(authorityRepository.findById(2L).get());
            User savedUserServiceProvider = userRepository.save(userServiceProvider);
            ServiceProvider serviceProvider = new ServiceProvider();
            serviceProvider.setFullName("User ServiceProvider");
            serviceProvider.setCountry("Argentina");
            serviceProvider.setUser(savedUserServiceProvider);
            ServiceProvider savedServiceProvider = serviceProviderRepository.save(serviceProvider);
            savedUserServiceProvider.setServiceProvider(savedServiceProvider);
            userRepository.save(savedUserServiceProvider);
        }
    }

}
