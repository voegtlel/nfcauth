package de.infornautik.nfcauth

import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import androidx.recyclerview.widget.DiffUtil
import androidx.recyclerview.widget.ListAdapter
import androidx.recyclerview.widget.RecyclerView
import java.text.DateFormat
import java.util.Date

class ServiceRegistrationsAdapter(private val onRegistrationClick: (ServiceRegistration) -> Unit) :
    ListAdapter<ServiceRegistration, ServiceRegistrationsAdapter.RegistrationViewHolder>(RegistrationDiffCallback()) {

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): RegistrationViewHolder {
        val view = LayoutInflater.from(parent.context)
            .inflate(android.R.layout.simple_list_item_2, parent, false)
        return RegistrationViewHolder(view)
    }

    override fun onBindViewHolder(holder: RegistrationViewHolder, position: Int) {
        holder.bind(getItem(position))
    }

    inner class RegistrationViewHolder(itemView: View) : RecyclerView.ViewHolder(itemView) {
        private val title: TextView = itemView.findViewById(android.R.id.text1)
        private val subtitle: TextView = itemView.findViewById(android.R.id.text2)

        fun bind(registration: ServiceRegistration) {
            title.text = registration.serviceName
            val expiry = DateFormat.getDateInstance().format(Date(registration.registrationExpiresAt))
            subtitle.text = if (registration.registrationExpiresAt <= System.currentTimeMillis()) {
                itemView.context.getString(R.string.service_list_expired, registration.operatorName, expiry)
            } else {
                itemView.context.getString(R.string.service_list_expires, registration.operatorName, expiry)
            }
            itemView.setOnClickListener { onRegistrationClick(registration) }
        }
    }

    private class RegistrationDiffCallback : DiffUtil.ItemCallback<ServiceRegistration>() {
        override fun areItemsTheSame(oldItem: ServiceRegistration, newItem: ServiceRegistration): Boolean =
            oldItem.serviceOrigin == newItem.serviceOrigin &&
                oldItem.serviceId == newItem.serviceId &&
                oldItem.authenticationProfile == newItem.authenticationProfile

        override fun areContentsTheSame(oldItem: ServiceRegistration, newItem: ServiceRegistration): Boolean =
            oldItem == newItem
    }
}
