package org.example.oauthjwt.Controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
public class MyController {

    @GetMapping("/")
    @ResponseBody
    public String myAPI() {
        return "my route";
    }
}
