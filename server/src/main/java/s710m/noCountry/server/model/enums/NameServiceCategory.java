package s710m.noCountry.server.model.enums;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@AllArgsConstructor
@NoArgsConstructor
public enum NameServiceCategory {

    AC("Ac"),
    TILER("Tiler"),
    HEATER("Hater"),
    CARPENTER("Carpenter"),
    GLAZIERS("Glaziers"),
    ELDERLY_CARE("Elderly Care"),
    ELECTRICIAN("Electrician"),
    CEMENT_WORK("Cement Work"),
    LADDER("Ladder"),
    COVERS_ROOF("Covers Roof"),
    PLUMBER("Plumber"),
    HOME_REPAIR("Home Repair"),
    NANNY("Nanny"),
    WALLPAPER("Wallpaper"),
    PAINTER("Painter"),
    WALL_COVERING("Wall Covering"),
    FLOORS("Floors"),
    WASHER_TECHNICIAN("Washer Technician");

    private String name;

}
