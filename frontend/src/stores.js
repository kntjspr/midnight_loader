import { writable } from 'svelte/store'

export const logs = writable([])
export const status = writable('idle')
