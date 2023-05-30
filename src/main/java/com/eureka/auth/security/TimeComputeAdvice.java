package com.eureka.auth.security;

import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.springframework.stereotype.Component;

@Component
@Aspect
public class TimeComputeAdvice {
	
	@Around(value = "execution(* com.eureka.auth.security.UserDetailsServiceImpl.loadUserByUsername(..))")
	public Object compute(ProceedingJoinPoint proceedingJoinPoint) throws Throwable {
		  String methodName=proceedingJoinPoint.getSignature().getName();
		  long startTime = System.currentTimeMillis();
		  Object loadUserByUsername=proceedingJoinPoint.proceed();
		  
		  System.out.println("methodName is called - > "+methodName+" return = "+loadUserByUsername);
		  long endTime = System.currentTimeMillis();
		  long timeTaken = endTime-startTime;
		  System.out.println("Total time taken by = "+timeTaken);
		  return loadUserByUsername;
	}

}
