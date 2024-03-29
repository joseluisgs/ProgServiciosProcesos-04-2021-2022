/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package cifrador.vistas;

import cifrador.utils.Cifrador;

import javax.swing.*;
import javax.swing.filechooser.FileNameExtensionFilter;
import java.io.*;

/**
 * @author link
 */
public class AES extends javax.swing.JFrame {

    byte[] original;
    byte[] cifrado;
    byte[] pass;
    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton bCargar;
    private javax.swing.JButton bCifrar;
    private javax.swing.JButton bDescifrar;
    private javax.swing.JButton bLimpiar;
    private javax.swing.JButton bSalvar;
    private javax.swing.JButton jButton1;
    private javax.swing.JButton jButton2;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel jLabel2;
    private javax.swing.JLabel jLabel3;
    private javax.swing.JLabel jLabel4;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JScrollPane jScrollPane2;
    private javax.swing.JTextArea tCifrado;
    private javax.swing.JPasswordField tClave;
    private javax.swing.JTextArea tOriginal;
    /**
     * Creates new form SHA
     */
    public AES() {
        initComponents();
        limpiar();
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
            java.util.logging.Logger.getLogger(AES.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (InstantiationException ex) {
            java.util.logging.Logger.getLogger(AES.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (IllegalAccessException ex) {
            java.util.logging.Logger.getLogger(AES.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (javax.swing.UnsupportedLookAndFeelException ex) {
            java.util.logging.Logger.getLogger(AES.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        }
        //</editor-fold>
        //</editor-fold>

        /* Create and display the form */
        java.awt.EventQueue.invokeLater(new Runnable() {
            public void run() {
                new AES().setVisible(true);
            }
        });
    }

    private void limpiar() {
        this.tCifrado.setText("");
        this.tOriginal.setText("");
        this.tClave.setText("");
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
        jScrollPane1 = new javax.swing.JScrollPane();
        tOriginal = new javax.swing.JTextArea();
        jLabel3 = new javax.swing.JLabel();
        jScrollPane2 = new javax.swing.JScrollPane();
        tCifrado = new javax.swing.JTextArea();
        bSalvar = new javax.swing.JButton();
        bLimpiar = new javax.swing.JButton();
        bDescifrar = new javax.swing.JButton();
        jLabel4 = new javax.swing.JLabel();
        tClave = new javax.swing.JPasswordField();
        bCargar = new javax.swing.JButton();
        bCifrar = new javax.swing.JButton();
        jButton1 = new javax.swing.JButton();
        jButton2 = new javax.swing.JButton();

        setDefaultCloseOperation(javax.swing.WindowConstants.DISPOSE_ON_CLOSE);

        jLabel1.setFont(new java.awt.Font("Lucida Grande", 1, 18)); // NOI18N
        jLabel1.setText("AES");

        jLabel2.setText("Texto:");

        tOriginal.setColumns(20);
        tOriginal.setRows(5);
        jScrollPane1.setViewportView(tOriginal);

        jLabel3.setText("Cifrado:");

        tCifrado.setEditable(false);
        tCifrado.setColumns(20);
        tCifrado.setRows(5);
        jScrollPane2.setViewportView(tCifrado);

        bSalvar.setText("Salvar");
        bSalvar.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                bSalvarActionPerformed(evt);
            }
        });

        bLimpiar.setText("Limpiar");
        bLimpiar.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                bLimpiarActionPerformed(evt);
            }
        });

        bDescifrar.setText("Descifrar");
        bDescifrar.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                bDescifrarActionPerformed(evt);
            }
        });

        jLabel4.setText("Clave:");

        bCargar.setText("Cargar");
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

        jButton1.setText("Salvar");
        jButton1.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButton1ActionPerformed(evt);
            }
        });

        jButton2.setText("Recuperar");
        jButton2.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButton2ActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
                layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                        .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                                        .addGroup(layout.createSequentialGroup()
                                                .addContainerGap()
                                                .addComponent(jScrollPane1))
                                        .addGroup(javax.swing.GroupLayout.Alignment.LEADING, layout.createSequentialGroup()
                                                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                                                        .addGroup(javax.swing.GroupLayout.Alignment.LEADING, layout.createSequentialGroup()
                                                                .addContainerGap()
                                                                .addComponent(jLabel2))
                                                        .addGroup(javax.swing.GroupLayout.Alignment.LEADING, layout.createSequentialGroup()
                                                                .addContainerGap()
                                                                .addComponent(jLabel3)))
                                                .addGap(0, 0, Short.MAX_VALUE)))
                                .addContainerGap())
                        .addGroup(layout.createSequentialGroup()
                                .addContainerGap()
                                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                        .addGroup(layout.createSequentialGroup()
                                                .addComponent(bCifrar)
                                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                                .addComponent(bDescifrar)
                                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                                .addComponent(bLimpiar)
                                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                                .addComponent(bCargar)
                                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                                .addComponent(bSalvar))
                                        .addComponent(jScrollPane2, javax.swing.GroupLayout.Alignment.TRAILING)
                                        .addGroup(layout.createSequentialGroup()
                                                .addComponent(jLabel4)
                                                .addGap(9, 9, 9)
                                                .addComponent(tClave, javax.swing.GroupLayout.PREFERRED_SIZE, 301, javax.swing.GroupLayout.PREFERRED_SIZE)
                                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                                .addComponent(jButton1)
                                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                                .addComponent(jButton2)
                                                .addGap(0, 0, Short.MAX_VALUE)))
                                .addContainerGap())
                        .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                                .addGap(0, 0, Short.MAX_VALUE)
                                .addComponent(jLabel1)
                                .addGap(238, 238, 238))
        );
        layout.setVerticalGroup(
                layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                        .addGroup(layout.createSequentialGroup()
                                .addComponent(jLabel1)
                                .addGap(22, 22, 22)
                                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                                        .addComponent(jLabel4)
                                        .addComponent(tClave, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                                        .addComponent(jButton1)
                                        .addComponent(jButton2))
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                .addComponent(jLabel2)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addComponent(jScrollPane1, javax.swing.GroupLayout.PREFERRED_SIZE, 100, javax.swing.GroupLayout.PREFERRED_SIZE)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addComponent(jLabel3)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addComponent(jScrollPane2, javax.swing.GroupLayout.PREFERRED_SIZE, 100, javax.swing.GroupLayout.PREFERRED_SIZE)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                                        .addComponent(bDescifrar)
                                        .addComponent(bLimpiar)
                                        .addComponent(bSalvar)
                                        .addComponent(bCargar)
                                        .addComponent(bCifrar))
                                .addContainerGap())
        );

        pack();
    }// </editor-fold>//GEN-END:initComponents

    private void bLimpiarActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_bLimpiarActionPerformed
        // TODO add your handling code here:
        this.limpiar();
    }//GEN-LAST:event_bLimpiarActionPerformed

    private void bSalvarActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_bSalvarActionPerformed
        // TODO add your handling code here:
        salvar();
    }//GEN-LAST:event_bSalvarActionPerformed

    private void bDescifrarActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_bDescifrarActionPerformed
        // TODO add your handling code here:
        descifrar();
    }//GEN-LAST:event_bDescifrarActionPerformed

    private void bCargarActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_bCargarActionPerformed
        // TODO add your handling code here:
        cargar();
    }//GEN-LAST:event_bCargarActionPerformed

    private void bCifrarActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_bCifrarActionPerformed
        // TODO add your handling code here:
        cifrar();
    }//GEN-LAST:event_bCifrarActionPerformed

    private void jButton1ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButton1ActionPerformed
        // TODO add your handling code here:
        salvarClave();
    }//GEN-LAST:event_jButton1ActionPerformed

    private void jButton2ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButton2ActionPerformed
        // TODO add your handling code here:
        recuperarClave();
    }//GEN-LAST:event_jButton2ActionPerformed
    // End of variables declaration//GEN-END:variables

    private void salvar() {
        // Primero es obtener la ruta del fichero a guardar con un elemento de la interfaz
        JFileChooser elegirRuta = new JFileChooser();
        elegirRuta.setDialogTitle("Indica el nombre del Fichero");
        FileNameExtensionFilter filtroFichero = new FileNameExtensionFilter("DAT", "dat");
        elegirRuta.setFileFilter(filtroFichero);
        int seleccion = elegirRuta.showSaveDialog(this);
        // Si pulsa guardar o aceptar
        if (seleccion == JFileChooser.APPROVE_OPTION) {
            File fichero = elegirRuta.getSelectedFile();
            //System.out.println("fichero " + fichero.getAbsolutePath());
            escribirFichero(this.tCifrado.getText(), fichero);
            // guardamos el fichero como sabemos
            //imprimirFichero(fichero);

        }
    }

    private void escribirFichero(String mensaje, File fichero) {
        try {
            PrintWriter ficheroSalida = new PrintWriter(
                    new FileWriter(fichero));

            ficheroSalida.println(mensaje);
            ficheroSalida.close();
            JOptionPane.showMessageDialog(null, "Fichero salvado con éxito en: " + fichero.getPath(), "Fichero salvado", JOptionPane.INFORMATION_MESSAGE);
        } catch (IOException ex) {
            JOptionPane.showMessageDialog(null, ex.getMessage(), "Error al salvar fichero", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void cifrar() {
        if (this.tClave.getText().length() >= 16) {
            Cifrador c = Cifrador.nuevoCifrador();
            String sal = c.cifrarAES(this.tOriginal.getText(), this.tClave.getText());
            this.tCifrado.setText(sal);
        } else {
            JOptionPane.showMessageDialog(this, "La longitud de la clave debe ser mayor a 16 caracteres", "Longitud insuficiente", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void descifrar() {
        if (this.tClave.getText().length() >= 16) {
            Cifrador c = Cifrador.nuevoCifrador();
            String sal = c.descifrarAES(this.tOriginal.getText(), this.tClave.getText());
            this.tCifrado.setText(sal);
        } else {
            JOptionPane.showMessageDialog(this, "La longitud de la clave debe ser mayor a 16 caracteres", "Longitud insuficiente", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void cargar() {
        // Primero es obtener la ruta del fichero a guardar con un elemento de la interfaz
        JFileChooser elegirRuta = new JFileChooser();
        elegirRuta.setDialogTitle("Indica el nombre del Fichero");
        FileNameExtensionFilter filtroFichero = new FileNameExtensionFilter("DAT", "dat");
        elegirRuta.setFileFilter(filtroFichero);
        int seleccion = elegirRuta.showOpenDialog(this);
        // Si pulsa guardar o aceptar
        if (seleccion == JFileChooser.APPROVE_OPTION) {
            File fichero = elegirRuta.getSelectedFile();
            //System.out.println("fichero " + fichero.getAbsolutePath());
            leerFichero(fichero);
            // guardamos el fichero como sabemos
            //imprimirFichero(fichero);

        }
    }

    private void leerFichero(File fichero) {
        try {
            BufferedReader ficheroEntrada = new BufferedReader(
                    new FileReader(fichero));

            String linea = null;
            String sal = "";
            while ((linea = ficheroEntrada.readLine()) != null) {
                sal += linea;
            }
            this.limpiar();

            this.tOriginal.setText(sal);
            ficheroEntrada.close();
            JOptionPane.showMessageDialog(null, "Fichero importado con éxito en: " + fichero.getPath(), "Fichero importado", JOptionPane.INFORMATION_MESSAGE);
        } catch (IOException ex) {
            JOptionPane.showMessageDialog(null, ex.getMessage(), "Error al importar fichero", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void salvarClave() {
        Cifrador.nuevoCifrador().salvarClaveAES(this.tClave.getText(), "clave_aes.dat");
    }

    private void recuperarClave() {
        String sal = Cifrador.nuevoCifrador().cargarClaveAES("clave_aes.dat");
        //System.out.println(sal);
        this.tClave.setText(sal);
    }

}
