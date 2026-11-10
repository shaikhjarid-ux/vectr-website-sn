// Browser entry: wires the real scan engine into the page.
import { scan } from '../engine/scan.js';
import { startApp } from './start.js';

startApp(document, { scan });
