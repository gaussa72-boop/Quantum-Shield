import React from "react";
import { SafeAreaView, StatusBar, StyleSheet, Text, View } from "react-native";
import { WebView } from "react-native-webview";
const APP_URL = process.env.EXPO_PUBLIC_APP_URL;
export default function App() {
  return <SafeAreaView style={s.root}>
    <StatusBar barStyle="light-content" backgroundColor="#080B14" />
    {APP_URL ? <WebView source={{uri:APP_URL}} style={s.web} javaScriptEnabled domStorageEnabled /> :
      <View style={s.center}><Text style={s.brand}>ASTRALIS · QUANTUM SHIELD</Text>
      <Text style={s.title}>Dein digitaler Workspace</Text>
      <Text style={s.copy}>Die native iOS- und Android-App ist vorbereitet. Die sichere Verbindung zum Render-Webservice wird nach Bereitstellung der Backend-Adresse aktiviert.</Text></View>}
  </SafeAreaView>;
}
const s=StyleSheet.create({root:{flex:1,backgroundColor:"#080B14"},web:{flex:1,backgroundColor:"#080B14"},center:{flex:1,justifyContent:"center",padding:28},brand:{color:"#D7B76A",letterSpacing:3,fontSize:12,marginBottom:20},title:{color:"#F5F2EA",fontSize:30,fontWeight:"700",marginBottom:14},copy:{color:"#A8B0C0",fontSize:16,lineHeight:24}});
