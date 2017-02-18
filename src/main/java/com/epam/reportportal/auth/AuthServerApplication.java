/*
 * Copyright 2016 EPAM Systems
 *
 *
 * This file is part of EPAM Report Portal.
 * https://github.com/reportportal/service-authorization
 *
 * Report Portal is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Report Portal is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Report Portal.  If not, see <http://www.gnu.org/licenses/>.
 */
package com.epam.reportportal.auth;

import com.epam.reportportal.auth.store.entity.OAuth2AccessTokenEntity;
import com.epam.ta.reportportal.config.CacheConfiguration;
import com.epam.ta.reportportal.config.MongodbConfiguration;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.thymeleaf.ThymeleafAutoConfiguration;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.data.mongodb.repository.config.EnableMongoRepositories;
import org.springframework.social.connect.web.thymeleaf.SpringSocialDialect;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.servlet.ViewResolver;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import org.thymeleaf.spring4.SpringTemplateEngine;
import org.thymeleaf.spring4.view.ThymeleafViewResolver;
import org.thymeleaf.templateresolver.ClassLoaderTemplateResolver;
import org.thymeleaf.templateresolver.TemplateResolver;

import java.util.Optional;

//import org.springframework.session.data.mongo.AbstractMongoSessionConverter;
//import org.springframework.session.data.mongo.JdkMongoSessionConverter;
//import org.springframework.session.data.mongo.config.annotation.web.http.EnableMongoHttpSession;

/**
 * Application entry point
 *
 * @author <a href="mailto:andrei_varabyeu@epam.com">Andrei Varabyeu</a>
 */
@SpringBootApplication(exclude = ThymeleafAutoConfiguration.class)
@Import({ MongodbConfiguration.class, CacheConfiguration.class })
@EnableDiscoveryClient
@EnableMongoRepositories(basePackageClasses = OAuth2AccessTokenEntity.class)
@EnableWebMvc
public class AuthServerApplication {

	public static void main(String[] args) {
		//workaround for https://github.com/spring-projects/spring-boot/issues/8234
		Optional.ofNullable(System.getenv("rp.profiles")).ifPresent(p -> System.setProperty("spring.profiles.active",p));

		SpringApplication.run(AuthServerApplication.class, args);
	}

    /*
	 * Mongo HTTP session is used to share session between several instances
     * Actually, authentication is stateless, but we need session storage to handle Authorization Flow
     * of GitHub OAuth. This is alse the reason why there is requestContextListener - just to make
     * request scope beans available for session commit during {@link org.springframework.session.web.http.SessionRepositoryFilter}
     * execution
     */
	//    @Configuration
	//    @EnableMongoHttpSession
	//    public static class MvcConfig extends WebMvcConfigurerAdapter {
	//
	//        @Autowired
	//        private HttpMessageConverters messageConverters;
	//
	//        @Bean
	//        public AbstractMongoSessionConverter mongoSessionConverter(){
	//            return new JdkMongoSessionConverter();
	//        }
	//
	//        @Override
	//        public void configureHandlerExceptionResolvers(List<HandlerExceptionResolver> exceptionResolvers) {
	//            RestExceptionHandler handler = new RestExceptionHandler();
	//            handler.setOrder(Ordered.HIGHEST_PRECEDENCE + 1);
	//
	//            DefaultErrorResolver defaultErrorResolver = new DefaultErrorResolver(ExceptionMappings.DEFAULT_MAPPING);
	//            handler.setErrorResolver(new ReportPortalExceptionResolver(defaultErrorResolver));
	//            handler.setMessageConverters(messageConverters.getConverters());
	//            exceptionResolvers.add(handler);
	//        }
	//    }


	@Bean
	public ViewResolver viewResolver(SpringTemplateEngine templateEngine) {
		ThymeleafViewResolver viewResolver = new ThymeleafViewResolver();
		viewResolver.setTemplateEngine(templateEngine);
		return viewResolver;
	}

	@Bean
	public SpringTemplateEngine templateEngine(TemplateResolver templateResolver) {
		SpringTemplateEngine templateEngine = new SpringTemplateEngine();
		templateEngine.setTemplateResolver(templateResolver);
		templateEngine.addDialect(new SpringSocialDialect());
		return templateEngine;
	}

	@Bean
	public TemplateResolver templateResolver() {
		TemplateResolver templateResolver = new ClassLoaderTemplateResolver();
		templateResolver.setPrefix("views/");
		templateResolver.setSuffix(".html");
		templateResolver.setTemplateMode("HTML5");
		return templateResolver;
	}

	@Controller
	public class HomeController {
		@RequestMapping(value = "/", method = RequestMethod.GET)
		public String home(Model model) {
			return "home";
		}

		@RequestMapping(value = "/signin", method = RequestMethod.GET)
		public String signin(Model model) {
			return "signin";
		}
	}

}
