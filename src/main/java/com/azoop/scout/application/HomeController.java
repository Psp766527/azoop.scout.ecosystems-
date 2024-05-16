package com.azoop.scout.application;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/public")
public class HomeController {

    @PreAuthorize("hasRole('NORMAL')")
    @GetMapping("/home")
    public String home() {
        return "<!DOCTYPE html>\n" +
                "<html>\n" +
                "<head>\n" +
                "  <title>User Details Form</title>\n" +
                "  <link rel=\"stylesheet\" type=\"text/css\" href=\"styles.css\">\n" +
                "</head>\n" +
                "<body>\n" +
                "  <h1>User Details Form</h1>\n" +
                "  \n" +
                "  <form action=\"submit.php\" method=\"POST\">\n" +
                "    <div class=\"form-group\">\n" +
                "      <label for=\"name\">Name:</label>\n" +
                "      <input type=\"text\" id=\"name\" name=\"name\" required>\n" +
                "    </div>\n" +
                "    \n" +
                "    <div class=\"form-group\">\n" +
                "      <label for=\"email\">Email:</label>\n" +
                "      <input type=\"email\" id=\"email\" name=\"email\" required>\n" +
                "    </div>\n" +
                "    \n" +
                "    <div class=\"form-group\">\n" +
                "      <label for=\"age\">Age:</label>\n" +
                "      <input type=\"number\" id=\"age\" name=\"age\" required>\n" +
                "    </div>\n" +
                "    \n" +
                "    <div class=\"form-group\">\n" +
                "      <label for=\"gender\">Gender:</label>\n" +
                "      <select id=\"gender\" name=\"gender\" required>\n" +
                "        <option value=\"\">Select</option>\n" +
                "        <option value=\"male\">Male</option>\n" +
                "        <option value=\"female\">Female</option>\n" +
                "        <option value=\"other\">Other</option>\n" +
                "      </select>\n" +
                "    </div>\n" +
                "    \n" +
                "    <div class=\"form-group\">\n" +
                "      <input type=\"submit\" value=\"Submit\">\n" +
                "    </div>\n" +
                "  </form>\n" +
                "</body>\n" +
                "</html>";
    }


}
