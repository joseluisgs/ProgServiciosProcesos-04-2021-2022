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
public class FicheroAES extends javax.swing.JFrame {

    File fichero = null;
    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton bCargar;
    private javax.swing.JButton bCifrar;
    private javax.swing.JButton bDescifrar;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel jLabel2;
    private javax.swing.JLabel jLabel4;
    private javax.swing.JPasswordField tClave;
    private javax.swing.JTextField tFichero;
    /**
     * Creates new form DSA
     */
    public FicheroAES() {
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
            java.util.logging.Logger.getLogger(FicheroAES.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (InstantiationException ex) {
            java.util.logging.Logger.getLogger(FicheroAES.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (IllegalAccessException ex) {
            java.util.logging.Logger.getLogger(FicheroAES.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (javax.swing.UnsupportedLookAndFeelException ex) {
            java.util.logging.Logger.getLogger(FicheroAES.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
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
                new FicheroAES().setVisible(true);
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
        tFichero = new javax.swing.JTextField();
        tClave = new javax.swing.JPasswordField();

        setDefaultCloseOperation(javax.swing.WindowConstants.DISPOSE_ON_CLOSE);

        jLabel1.setFont(new java.awt.Font("Lucida Grande", 1, 18)); // NOI18N
        jLabel1.setText("Cifrar / Descifrar Fichero AES");

        jLabel2.setText("Fichero: ");

        bDescifrar.setText("Descifrar");
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

        bCifrar.setText("Cifrar");
        bCifrar.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                bCifrarActionPerformed(evt);
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
                                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                                        .addComponent(tFichero, javax.swing.GroupLayout.DEFAULT_SIZE, 325, Short.MAX_VALUE)
                                        .addComponent(tClave))
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addComponent(bCargar)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addComponent(bCifrar)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addComponent(bDescifrar)
                                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                        .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                                .addContainerGap(211, Short.MAX_VALUE)
                                .addComponent(jLabel1)
                                .addGap(185, 185, 185))
        );
        layout.setVerticalGroup(
                layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                        .addGroup(layout.createSequentialGroup()
                                .addContainerGap()
                                .addComponent(jLabel1)
                                .addGap(16, 16, 16)
                                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                                        .addComponent(jLabel4)
                                        .addComponent(tClave, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, 9, Short.MAX_VALUE)
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
        descifrar();
    }//GEN-LAST:event_bDescifrarActionPerformed

    private void bCargarActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_bCargarActionPerformed
        // TODO add your handling code here:
        abrirFichero();
    }//GEN-LAST:event_bCargarActionPerformed

    private void bCifrarActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_bCifrarActionPerformed
        // TODO add your handling code here:
        cifrar();
    }//GEN-LAST:event_bCifrarActionPerformed
    // End of variables declaration//GEN-END:variables

    private void cifrar() {
        JFileChooser elegirRuta = new JFileChooser();
        elegirRuta.setDialogTitle("Indica el nombre para guardar el fichero cifrado");
        FileNameExtensionFilter filtroFichero = new FileNameExtensionFilter("CIF", "cif");
        elegirRuta.setFileFilter(filtroFichero);
        int seleccion = elegirRuta.showSaveDialog(this);
        // Si pulsa guardar o aceptar
        if (seleccion == JFileChooser.APPROVE_OPTION && this.tClave.getText().length() >= 16) {
            File destino = elegirRuta.getSelectedFile();
            Cifrador c = Cifrador.nuevoCifrador();
            c.cifrarFicheroAES(this.fichero, destino, this.tClave.getText());
            JOptionPane.showMessageDialog(this, "Fichero: " + this.fichero.getName() + " cifrado con éxito en :" + destino.getAbsolutePath(), "Fichero cifrado", JOptionPane.INFORMATION_MESSAGE);

        } else {
            JOptionPane.showMessageDialog(this, "Fichero o clave incorrecta", "Problema al cifrar", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void descifrar() {
        JFileChooser elegirRuta = new JFileChooser();
        elegirRuta.setDialogTitle("Indica el nombre para guardar el fichero descifrado");
        //FileNameExtensionFilter filtroFichero = new FileNameExtensionFilter("CIF", "cif");
        //elegirRuta.setFileFilter(filtroFichero);
        int seleccion = elegirRuta.showSaveDialog(this);
        // Si pulsa guardar o aceptar
        if (seleccion == JFileChooser.APPROVE_OPTION && this.tClave.getText().length() >= 16) {
            File destino = elegirRuta.getSelectedFile();
            Cifrador c = Cifrador.nuevoCifrador();
            c.descifrarFicheroAES(this.fichero, destino, this.tClave.getText());
            JOptionPane.showMessageDialog(this, "Fichero: " + this.fichero.getName() + " descifrado con éxito en :" + destino.getAbsolutePath(), "Fichero descifrado", JOptionPane.INFORMATION_MESSAGE);

        } else {
            JOptionPane.showMessageDialog(this, "Fichero o clave incorrecta", "Problema al cifrar", JOptionPane.ERROR_MESSAGE);
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

    /*
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
     */
}