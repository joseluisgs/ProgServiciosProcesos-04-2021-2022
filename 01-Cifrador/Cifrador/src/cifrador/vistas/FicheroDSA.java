/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package cifrador.vistas;

import cifrador.utils.Cifrador;

import javax.swing.*;
import javax.swing.filechooser.FileNameExtensionFilter;
import java.io.File;

/**
 * @author link
 */
public class FicheroDSA extends javax.swing.JFrame {

    File fichero = null;
    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton bCargar;
    private javax.swing.JButton bCifrar;
    private javax.swing.JButton bDescifrar;
    private javax.swing.JButton jButton2;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel jLabel2;
    private javax.swing.JLabel jLabel4;
    private javax.swing.JTextField tFichero;
    /**
     * Creates new form DSA
     */
    public FicheroDSA() {
        initComponents();
        this.bCifrar.setEnabled(false);
        this.bDescifrar.setEnabled(false);
    }

    /**
     * @param args the command line arguments
     */
    public static void main(String args[]) {
        /* Set the Nimbus look and feel */
        //<editor-fold defaultstate="collapsed" desc=" Look and feel setting code (optional) ">
        /* If Nimbus (introduced in Java SE 6) is not available, stay with the default look and feel.
         * For details see http://download.oracle.com/javase/tutorial/uiswing/lookandfeel/plaf.html
         */
        try {
            for (javax.swing.UIManager.LookAndFeelInfo info : javax.swing.UIManager.getInstalledLookAndFeels()) {
                if ("Nimbus".equals(info.getName())) {
                    javax.swing.UIManager.setLookAndFeel(info.getClassName());
                    break;
                }
            }
        } catch (ClassNotFoundException ex) {
            java.util.logging.Logger.getLogger(FicheroDSA.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (InstantiationException ex) {
            java.util.logging.Logger.getLogger(FicheroDSA.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (IllegalAccessException ex) {
            java.util.logging.Logger.getLogger(FicheroDSA.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (javax.swing.UnsupportedLookAndFeelException ex) {
            java.util.logging.Logger.getLogger(FicheroDSA.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        }
        //</editor-fold>
        //</editor-fold>
        //</editor-fold>
        //</editor-fold>
        //</editor-fold>
        //</editor-fold>
        //</editor-fold>
        //</editor-fold>
        //</editor-fold>
        //</editor-fold>
        //</editor-fold>
        //</editor-fold>
        //</editor-fold>
        //</editor-fold>
        //</editor-fold>
        //</editor-fold>

        /* Create and display the form */
        java.awt.EventQueue.invokeLater(new Runnable() {
            public void run() {
                new FicheroDSA().setVisible(true);
            }
        });
    }

    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        jLabel1 = new javax.swing.JLabel();
        jLabel2 = new javax.swing.JLabel();
        bDescifrar = new javax.swing.JButton();
        jLabel4 = new javax.swing.JLabel();
        bCargar = new javax.swing.JButton();
        bCifrar = new javax.swing.JButton();
        jButton2 = new javax.swing.JButton();
        tFichero = new javax.swing.JTextField();

        setDefaultCloseOperation(javax.swing.WindowConstants.DISPOSE_ON_CLOSE);

        jLabel1.setFont(new java.awt.Font("Lucida Grande", 1, 18)); // NOI18N
        jLabel1.setText("Firmar / Validar Fichero");

        jLabel2.setText("Fichero: ");

        bDescifrar.setText("Validar");
        bDescifrar.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                bDescifrarActionPerformed(evt);
            }
        });

        jLabel4.setText("Clave:");

        bCargar.setText("Abrir");
        bCargar.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                bCargarActionPerformed(evt);
            }
        });

        bCifrar.setText("Firmar");
        bCifrar.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                bCifrarActionPerformed(evt);
            }
        });

        jButton2.setText("Generar Clave Pública y Privada");
        jButton2.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButton2ActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
                layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                        .addGroup(layout.createSequentialGroup()
                                .addContainerGap()
                                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                                        .addComponent(jLabel4, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                        .addComponent(jLabel2, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                        .addGroup(layout.createSequentialGroup()
                                                .addComponent(tFichero, javax.swing.GroupLayout.PREFERRED_SIZE, 325, javax.swing.GroupLayout.PREFERRED_SIZE)
                                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                                .addComponent(bCargar)
                                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                                .addComponent(bCifrar)
                                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                                .addComponent(bDescifrar))
                                        .addComponent(jButton2))
                                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                        .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                .addComponent(jLabel1)
                                .addGap(217, 217, 217))
        );
        layout.setVerticalGroup(
                layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                        .addGroup(layout.createSequentialGroup()
                                .addGap(4, 4, 4)
                                .addComponent(jLabel1)
                                .addGap(18, 18, 18)
                                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                                        .addComponent(jLabel4)
                                        .addComponent(jButton2))
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                                        .addComponent(jLabel2)
                                        .addComponent(tFichero, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                                        .addComponent(bCifrar)
                                        .addComponent(bCargar)
                                        .addComponent(bDescifrar))
                                .addGap(17, 17, 17))
        );

        pack();
    }// </editor-fold>//GEN-END:initComponents

    private void bDescifrarActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_bDescifrarActionPerformed
        // TODO add your handling code here:
        verificar();
    }//GEN-LAST:event_bDescifrarActionPerformed

    private void bCargarActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_bCargarActionPerformed
        // TODO add your handling code here:
        abrirFichero();
    }//GEN-LAST:event_bCargarActionPerformed

    private void bCifrarActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_bCifrarActionPerformed
        // TODO add your handling code here:
        firmar();
    }//GEN-LAST:event_bCifrarActionPerformed

    private void jButton2ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButton2ActionPerformed
        // TODO add your handling code here:
        generarClaves();
    }//GEN-LAST:event_jButton2ActionPerformed
    // End of variables declaration//GEN-END:variables

    private void firmar() {
        JFileChooser elegirRuta = new JFileChooser();

        elegirRuta.setDialogTitle("Indica el nombre del Fichero de Clave Privada");
        FileNameExtensionFilter filtroFichero = new FileNameExtensionFilter("DAT", "dat");
        elegirRuta.setFileFilter(filtroFichero);
        int seleccion = elegirRuta.showOpenDialog(this);
        // Si pulsa guardar o aceptar
        if (seleccion == JFileChooser.APPROVE_OPTION) {
            File clavePrivada = elegirRuta.getSelectedFile();
            // Repetimos para la sesión. Se puede hacer más eficiente, pero estoy reutilizando todo
            elegirRuta.setDialogTitle("Indica el nombre para la firma");
            filtroFichero = new FileNameExtensionFilter("FIR", "fir");
            elegirRuta.setFileFilter(filtroFichero);
            seleccion = elegirRuta.showSaveDialog(this);
            if (seleccion == JFileChooser.APPROVE_OPTION) {
                File firma = elegirRuta.getSelectedFile();

                Cifrador c = Cifrador.nuevoCifrador();
                c.firmarFicheroDSA(this.fichero, clavePrivada, firma);
                JOptionPane.showMessageDialog(this, "Fichero: " + this.fichero.getName() + " Firmado con éxito en :" + firma.getAbsolutePath(), "Fichero firmado", JOptionPane.INFORMATION_MESSAGE);
            }

        }
    }

    private void verificar() {
        JFileChooser elegirRuta = new JFileChooser();
        elegirRuta.setDialogTitle("Indica el nombre del Fichero de Clave Pública");
        FileNameExtensionFilter filtroFichero = new FileNameExtensionFilter("DAT", "dat");
        elegirRuta.setFileFilter(filtroFichero);
        int seleccion = elegirRuta.showOpenDialog(this);
        // Si pulsa guardar o aceptar
        if (seleccion == JFileChooser.APPROVE_OPTION) {
            File clavePublica = elegirRuta.getSelectedFile();
            // Repetimos para la sesión. Se puede hacer más eficiente, pero estoy reutilizando todo
            elegirRuta.setDialogTitle("Indica el nombre para la firma");
            filtroFichero = new FileNameExtensionFilter("FIR", "fir");
            elegirRuta.setFileFilter(filtroFichero);
            seleccion = elegirRuta.showOpenDialog(this);
            if (seleccion == JFileChooser.APPROVE_OPTION) {
                File firma = elegirRuta.getSelectedFile();

                Cifrador c = Cifrador.nuevoCifrador();
                boolean sal = c.verificarFicheroDSA(this.fichero, clavePublica, firma);
                if (sal) {
                    JOptionPane.showMessageDialog(this, "Las firmas coinciden, no ha habido cambios en el fichero y se comprueba la identidad del autor", "Firmas correctas", JOptionPane.INFORMATION_MESSAGE);
                } else {
                    JOptionPane.showMessageDialog(this, "Las firmas no coinciden, ha habidos cambios en el fichero o en en la persona que lo firma no es quien dice ser", "Firmas incorrecta", JOptionPane.ERROR_MESSAGE);
                }
            }

        }
    }

    private void abrirFichero() {
        // Primero es obtener la ruta del fichero a guardar con un elemento de la interfaz
        JFileChooser elegirRuta = new JFileChooser();
        elegirRuta.setDialogTitle("Indica el nombre del Fichero Original");
        //FileNameExtensionFilter filtroFichero = new FileNameExtensionFilter("DAT", "dat");
        //elegirRuta.setFileFilter(filtroFichero);
        int seleccion = elegirRuta.showOpenDialog(this);
        // Si pulsa guardar o aceptar
        if (seleccion == JFileChooser.APPROVE_OPTION) {
            this.fichero = elegirRuta.getSelectedFile();
            this.bCifrar.setEnabled(true);
            this.bDescifrar.setEnabled(true);
            this.tFichero.setText(this.fichero.getAbsolutePath());
        }
    }

    private void generarClaves() {
        // Primero es obtener la ruta del fichero a guardar con un elemento de la interfaz
        JFileChooser elegirRuta = new JFileChooser();
        elegirRuta.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
        elegirRuta.setDialogTitle("Indica el nombre del de las claves");
        FileNameExtensionFilter filtroFichero = new FileNameExtensionFilter("DAT", "dat");
        elegirRuta.setFileFilter(filtroFichero);
        int seleccion = elegirRuta.showSaveDialog(this);
        // Si pulsa guardar o aceptar
        if (seleccion == JFileChooser.APPROVE_OPTION) {
            File claves = elegirRuta.getSelectedFile();
            Cifrador.nuevoCifrador().crearClavesDSA(claves.getAbsolutePath());

        }
    }

}
