package com.rest.test;
 
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.eclipse.jetty.servlet.ServletHolder;
 
public class App {
    public static void main(String[] args) throws Exception {
        ServletContextHandler context = new ServletContextHandler(ServletContextHandler.SESSIONS);
        context.setContextPath("/");
 
        Server jettyServer = new Server(8222);
        jettyServer.setHandler(context);
 
        ServletHolder jerseyServlet = context.addServlet(org.glassfish.jersey.servlet.ServletContainer.class, "/*");
        jerseyServlet.setInitOrder(0);
 
        // Tells the Jersey Servlet which REST service/class to load.
        jerseyServlet.setInitParameter("jersey.config.server.provider.classnames", TimestampProxy.class.getCanonicalName());

        //PDF Signature test
        //PdfSigner test_pdf = new PdfSigner();
        //test_pdf.signPdf("/home/ender_al/EclipseJEE/rest_example/restprj/src/MyExam.pdf","/home/ender_al/EclipseJEE/rest_example/restprj/src/MyExamSigned.pdf");
        try {
            jettyServer.start();
            jettyServer.join();
        } finally {
            jettyServer.destroy();
        }
    }
}
