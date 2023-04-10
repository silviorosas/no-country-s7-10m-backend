package s710m.noCountry.server.configException;

public class EntityFoundException extends RuntimeException{

    public EntityFoundException(){
        super("The record already exists in the database");
    }

    public EntityFoundException(String mensaje){
        super(mensaje);
    }

}
