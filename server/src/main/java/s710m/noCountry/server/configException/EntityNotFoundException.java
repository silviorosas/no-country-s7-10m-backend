package s710m.noCountry.server.configException;

import org.springframework.http.HttpStatus;

public class EntityNotFoundException extends RuntimeException{

    public EntityNotFoundException(){
        super("The record does not exist in the database");
    }

    public EntityNotFoundException(String mensaje){
        super(mensaje);
    }

}
