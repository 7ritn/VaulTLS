import 'bootstrap/dist/css/bootstrap.min.css';
import './assets/styles/variables.css'

import { createApp } from 'vue'
import { createPinia } from 'pinia'
import router from './router/router';

import App from './App.vue'

const app = createApp(App)
app.use(createPinia())
app.use(router);

app.mount('#app')
