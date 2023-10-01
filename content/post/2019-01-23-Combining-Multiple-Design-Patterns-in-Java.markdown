---
categories: Java
tags:
    - Java
    - Design Patterns
    - UML
date: "2019-01-23T19:15:02Z"
title: Combining Multiple Design Patterns in Java
---

For my designs patterns course, I had to design an application combining multiple Design Patterns and implement it in Java. Below is the given project description :

![Project Description](/assets/img/design-patterns/desc.png)

So, first of all we have to infer which design patterns we are supposed to use from the given text.
+ First sentence indicates we should use Observer Pattern
+ "Family of sensors" manufactured by different factories, so Abstract Factory Pattern it is
+ Adaptability for SMS, so Adapter Pattern will be used
+ Different commands will be executed, so Command Pattern should be used
+ Single object creation, so Singleton Pattern will be used

So, we are gonna have to combine 5 patterns to implement the application. First of all, let's see what the final output of the program will be like, and how the main function is implemented.

{{< highlight java >}}
    public class MainProject{
    public static void main(String[] arg) {
        SingleObject logFile = SingleObject.getInstance();

        SensorFactory factory;
        factory = new FactoryX();

        AlarmForMotion alarm = new AlarmForMotion();
        SprinklerForSmoke sprinkler = new SprinklerForSmoke();

        SensorForSmoke smokesensor =  factory.createSmokeSensor();
        SensorForMotion motionsensor = factory.createMotionSensor();

        SensorSystem sensorSystem = new SensorSystem();
        sensorSystem.register((SensorListener) smokesensor);
        sensorSystem.register((SensorListener) motionsensor);
        sensorSystem.notifyUser();

        HomeSecurityRemote remote = new HomeSecurityRemote();
        remote.setCommand(new StopAlarmCommand( alarm ));
        remote.buttonPressed();

        remote.setCommand(new TurnOffSprinklerCommand(sprinkler));
        remote.buttonPressed();
	    }
	}
{{< / highlight >}}

First we create the Singleton object. Second, as per the requirements, family of sensors should be produced by different factories. We create the factory with FactoryX and use it to produce motion and smoke sensors. Then the sensors are triggered and the user is notified. The remote is used to start and stop the Alarm and the Sprinkler.

So, we can see that (in order) Singleton, Observer, Abstract Factory and Command patterns have been used in Main. Only Adapter is missing, which is not directly called in main.

Let's start with the Singleton Pattern, as it will be the easiest to implement.

{{< highlight java >}}
    public class SingleObject {

    //create an object of SingleObject
    private static SingleObject instance = new SingleObject();
    //make the constructor private so that this class cannot be
    //instantiated
    private SingleObject(){}

    //Get the only object available
    public static SingleObject getInstance(){
        return instance;
    }

    public void showMessage(String s){
        System.out.println(s+" detected");
	    }
	}
{{< / highlight >}}

This piece of code is pretty much the same in all the examples you would find with a quick google search. Only in the showMessage function, we print a statement (normally to a log file, but anyways) to see that the object is created and created only once.

Now we can move on to the next line, creating the factory and the sensors. Let's see it in the class diagram first.

![Abstract Factory Class Diagram](/assets/img/design-patterns/factory.png)

Let's start with implementing the interface first, then we will write the concrete classes.

{{< highlight java >}}
    public interface SensorFactory {
		SensorForMotion createMotionSensor();
		SensorForSmoke createSmokeSensor();
	}
{{< / highlight >}}
	
Each factory will write code for this interface. In this scenario, I've created only two factories, FactoryX and FactoryY. Following is the code for their concrete classes:

{{< highlight java >}}
    public class FactoryX implements SensorFactory {

    @Override
    public SensorForMotion createMotionSensor() {
        return new XMotionSensor();
    }

    @Override
    public SensorForSmoke createSmokeSensor() {
        return new XSmokeSensor();
		}
	}
{{< / highlight >}}
	
***
{{< highlight java >}}
    public class FactoryY implements SensorFactory {

    @Override
    public SensorForMotion createMotionSensor() {
        return new YMotionSensor();
    }

    @Override
    public SensorForSmoke createSmokeSensor() {
        return new YSmokeSensor();
	    }
	}
{{< / highlight >}}

Now let's take a look at the class diagram for the sensors.

![Sensors](/assets/img/design-patterns/sensors.png)

SensorListener class is not of our concern right now, we will deal with it later when we implement the Observer Pattern. Again, let's start with the interfaces first, then move on to the concrete classes.

{{< highlight java >}}
    public interface SensorForSmoke {  
		String getDescription();  
	}
	
{{< / highlight >}}
***

{{< highlight java >}}
    public interface SensorForMotion {
        String getDescription();
    }
{{< / highlight >}}

Normally you would have a better function than getDescription, but since our application is not supposed to work and instead just print stuff, we will just implement it like this.

{{< highlight java >}}
    public class XSmokeSensor implements SensorForSmoke, SensorListener {
    
        static final String DESCRIPTION = "This is the FactoryX made Smoke Sensor.";
    
        @Override
        public String getDescription() {
            return DESCRIPTION;
        }
    
        public void detected() {
            Sms sms = new SmokeSmsAdapter(new SmokeSms());
    
            System.out.println("Smoke Sensor - Created by Factory X");
            sms.sendMessage("SMOKE detected");
    
            SprinklerForSmoke sprinkler = new SprinklerForSmoke();
            TurnOnSprinklerCommand turnon = new TurnOnSprinklerCommand(sprinkler);
            turnon.execute();
    
            SingleObject logFile = SingleObject.getInstance();
            logFile.showMessage("logfile: SMOKE");
    
        }
    }
    
{{< / highlight >}}
***

{{< highlight java >}}
    public class XMotionSensor implements SensorForMotion, SensorListener {
    
        static final String DESCRIPTION = "This is the FactoryX made Motion Sensor.";
    
        @Override
        public String getDescription() {
            return DESCRIPTION;
        }
    
        public void detected() {
            Sms sms = new MotionSmsAdapter(new MotionSms());
    
            System.out.println("Motion Sensor - Created by Factory X");
            sms.sendMessage("MOTION detected");
    
            //I could have invoked the alarm directly, but this is better suited for command pattern
            AlarmForMotion alarm = new AlarmForMotion();
            StartAlarmCommand start = new StartAlarmCommand(alarm);
            start.execute();
    
            SingleObject logFile = SingleObject.getInstance();
            logFile.showMessage("logfile: MOTION");
        }
    }
{{< / highlight >}}

Now that we have the Abstract Factory implemented, we get a better picture of how the sensors will work. And like I mentioned earlier, Adapter Pattern was not called in Main, but in the sensors. Let's see how the Adapter pattern is implemented in.

![SMS class diagram](/assets/img/design-patterns/sms.png)

Interface first:

{{< highlight java >}}
    public interface Sms {
    void sendMessage(String s);
	}
{{< / highlight >}}

Concrete classes:

{{< highlight java >}}
    public class MotionSmsAdapter implements Sms {
    private MotionSms adaptee;

    public MotionSmsAdapter(MotionSms motionsms){
        this.adaptee = motionsms;
    }

    @Override
    public void sendMessage(String s){
        System.out.println("SMS from MOTION ADAPTER: " +s);
        //here the message can be modified, adapted, whatever
        //we will just print a slightly modified message, that's it
	    }
	}
{{< / highlight >}}
	
***

{{< highlight java >}}
    public class SmokeSmsAdapter implements Sms {
        private SmokeSms adaptee;
    
        public SmokeSmsAdapter(SmokeSms smokesms){
            this.adaptee = smokesms;
        }
    
        @Override
        public void sendMessage(String s){
            System.out.println("SMS from SMOKE ADAPTER: " +s);
            //here the message can be modified, adapted, whatever
            //we will just print a slightly modified message, that's it
        }
    }
{{< / highlight >}}

***

{{< highlight java >}}
    public class MotionSms {
        public void sendMessage(String s){
            System.out.println("SMS from MOTION detector. Message is: "+s);
            //real SMS code goes here
        }
    }

{{< / highlight >}}
***

{{< highlight java >}}
    public class SmokeSms {
        public void sendMessage(String s){
            System.out.println("SMS from SMOKE detector. Message is: "+s);
            //real SMS code goes here
        }
    }
{{< / highlight >}}

Now let's look at how these sensors are used with Observer Pattern. Interface first:

{{< highlight java >}}
    interface SensorListener {
        void detected();
    }
{{< / highlight >}}
    
"detected" functionality was implemented in previous classes. So the only thing left is this class:

{{< highlight java >}}
    import java.util.Enumeration;  
    import java.util.Vector;  
      
    class SensorSystem {  
        private Vector listeners = new Vector();  
      
     public void register(SensorListener sensorListener) {  
            listeners.addElement(sensorListener);  
      }  
      
        public void notifyUser() {  
            for (Enumeration e = listeners.elements(); e.hasMoreElements();) {  
                ((SensorListener) e.nextElement()).detected();  
	    }  
       }  
   }
{{< / highlight >}}

Here we register the events that took place and let the objects call their detected functions when the notifyUser is called.

Now the only thing left is the Command pattern. In case you want to check on the Main function again to remember how it was called:

{{< highlight java >}}
    AlarmForMotion alarm = new AlarmForMotion();
    SprinklerForSmoke sprinkler = new SprinklerForSmoke();
    .
    .
    HomeSecurityRemote remote = new HomeSecurityRemote();  
    remote.setCommand(new StopAlarmCommand( alarm ));  
    remote.buttonPressed();  
      
    remote.setCommand(new TurnOffSprinklerCommand(sprinkler));  
    remote.buttonPressed();
{{< / highlight >}}

The class diagram:
![Command Pattern Class Diagram](/assets/img/design-patterns/command.png)

{{< highlight java >}}
    public interface Command {  
        public void execute();  
    }
{{< / highlight >}}
    
***

{{< highlight java >}}
    public class HomeSecurityRemote {
        Command command;
    
        public void setCommand(Command command) {
            this.command = command;
        }
    
        public void buttonPressed() {
            command.execute();
        }
    }
{{< / highlight >}}
    
***

{{< highlight java >}}
    public class TurnOffSprinklerCommand implements Command{
        SprinklerForSmoke sprinkler;
    
        public TurnOffSprinklerCommand(SprinklerForSmoke sprinkler) {
            super();
            this.sprinkler = sprinkler;
        }
    
        public void execute() {
            System.out.println("Turning off sprinkler.");
            sprinkler.turnOff();
        }
    }
{{< / highlight >}}

***

{{< highlight java >}}
    public class TurnOnSprinklerCommand implements Command{
        SprinklerForSmoke sprinkler;
    
        public TurnOnSprinklerCommand(SprinklerForSmoke sprinkler) {
            super();
            this.sprinkler = sprinkler;
        }
    
        public void execute() {
            System.out.println("Turning on sprinkler.");
            sprinkler.turnOn();
        }
    }
{{< / highlight >}}

***

{{< highlight java >}}
    public class StartAlarmCommand implements Command{  
        AlarmForMotion alarm;  
      
     public StartAlarmCommand(AlarmForMotion alarm) {  
            super();  
     this.alarm = alarm;  
      }  
      
        public void execute() {  
            System.out.println("Starting Alarm.");  
      alarm.start();  
      }  
    }
{{< / highlight >}}

***

{{< highlight java >}}
    public class StopAlarmCommand implements Command{
        AlarmForMotion alarm;
    
        public StopAlarmCommand(AlarmForMotion alarm) {
            super();
            this.alarm = alarm;
        }
    
        public void execute() {
            System.out.println("Stopping Alarm.");
            alarm.stop();
        }
    }
{{< / highlight >}}

***

{{< highlight java >}}
    public class SprinklerForSmoke {
        public  void turnOn() {
            System.out.println("Sprinkler is on");
        }
    
        public void turnOff() {
            System.out.println("Sprinkler is off");
        }
    }
{{< / highlight >}}

***

{{< highlight java >}}
    public class AlarmForMotion {
        void start() {
            System.out.println("Alarm Started..");
        }
    
        void stop() {
            System.out.println("Alarm stopped..");
        }
    }
{{< / highlight >}}

And with the command pattern finished, we are done with the program. Here is the final class diagram:
![Final class diagram](/assets/img/design-patterns/uml.png)

I would've preferred to put down a references/resources list, but unfortunately I did not keep track of that. But it was all in pretty much the first page results for related pattern name searches.

I've used simpleUML to generate the UML class diagrams.

You can check the  [Github Repo](/assets/DesignPatternsCode/DesignPatternsCode.zip) for the whole code.
That's it for this post, and feel free to reach out for adjustments/improvements on the post.

BTW, I fuckin hate Java, just sayin'
