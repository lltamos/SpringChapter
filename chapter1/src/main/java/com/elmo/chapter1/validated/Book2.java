package com.elmo.chapter1.validated;


import lombok.Data;

import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotNull;
import java.math.BigDecimal;

/**
 * @author Levin
 * @since 2018/6/5 0005
 */

/**
 * @author Levin
 * @since 2018/6/7 0005
 */
@Data
public class Book2 {

    @NotNull(message = "id 不能为空", groups = Groups.Update.class)
    private Integer id;
    @NotBlank(message = "name 不允许为空", groups = Groups.Default.class)
    private String name;
    @NotNull(message = "price 不允许为空", groups = Groups.Default.class)
    private BigDecimal price;

}
